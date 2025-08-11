from flask import Flask, request, jsonify
import os
import logging
import requests
from collections import defaultdict, deque
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import queue
from typing import Dict, List, DefaultDict, Deque
from datetime import datetime, timezone
import pytz

# 配置从环境变量获取
WECHAT_WEBHOOK_URL = os.getenv("WECHAT_WEBHOOK_URL",
                               "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=2b870a61-c53b-4bac-a1a7-1f21ff5434b4")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", "1000"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "20"))
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))

# 结构化日志配置
logging.basicConfig(
    level=LOG_LEVEL,
    format='{"time": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s", "file": "%(filename)s", "line": %(lineno)d}',
    handlers=[
        logging.FileHandler("alert_webhook.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 初始化队列和线程池
ALERT_QUEUE = queue.Queue(maxsize=QUEUE_MAXSIZE)
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)


# 频率限制器
class RateLimiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.message_timestamps: Deque[float] = deque()

    def is_allowed(self) -> bool:
        with self.lock:
            now = time.time()
            # 清理过期记录
            while self.message_timestamps and now - self.message_timestamps[0] > RATE_WINDOW:
                self.message_timestamps.popleft()

            if len(self.message_timestamps) < RATE_LIMIT:
                self.message_timestamps.append(now)
                return True
            return False


rate_limiter = RateLimiter()


# 统计服务
class StatsService:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {
            'total_received': 0,
            'total_processed': 0,
            'total_sent': 0,
            'total_failed': 0,
            'by_status': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_alertname': defaultdict(int),
            'rate_limited': 0,
            'queue_overflow': 0,
            'dedup_alerts': 0,
            'circuit_breaker_blocked': 0,
            'start_time': time.time()
        }

    def update(self, counter, value=1):
        with self.lock:
            if isinstance(counter, str):
                self.data[counter] += value
            elif isinstance(counter, dict):
                for key, val in counter.items():
                    if key in self.data:
                        if isinstance(self.data[key], defaultdict):
                            for sub_key, sub_val in val.items():
                                self.data[key][sub_key] += sub_val
                        else:
                            self.data[key] += val

    def get_stats(self):
        with self.lock:
            return self.data.copy()


stats_service = StatsService()


# 熔断器
class CircuitBreaker:
    def __init__(self):
        self.state = "closed"
        self.last_failure_time = 0
        self.failure_count = 0
        self.reset_timeout = 300
        self.failure_threshold = 5
        self.lock = threading.Lock()

    def check_state(self):
        with self.lock:
            if self.state == "open":
                if time.time() - self.last_failure_time > self.reset_timeout:
                    self.state = "half-open"
                    return True
                return False
            return True

    def record_failure(self):
        with self.lock:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                self.last_failure_time = time.time()
                logger.error("熔断器触发，停止发送告警消息")

    def record_success(self):
        with self.lock:
            if self.state == "half-open":
                self.state = "closed"
            self.failure_count = 0


circuit_breaker = CircuitBreaker()


# 告警处理器
class AlertProcessor:
    @staticmethod
    def process_and_group(alerts: List[Dict]) -> DefaultDict[str, List]:
        """处理告警并按告警名称分组（修复时间格式化问题）"""
        seen_fingerprints = set()
        grouped = defaultdict(list)

        for alert in alerts:
            fingerprint = hash(frozenset({
                                             'alertname': alert.get('labels', {}).get('alertname'),
                                             'summary': alert.get('annotations', {}).get('summary'),
                                             'severity': alert.get('labels', {}).get('severity'),
                                             'status': alert.get('status')
                                         }.items()))

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)

                labels = alert.get('labels', {})
                annotations = alert.get('annotations', {})
                alert_name = labels.get('alertname', '未知告警')
                status = alert.get('status', 'unknown')
                severity = labels.get('severity', 'unknown')

                # 修复时间格式化问题
                alert_time = alert.get('endsAt' if status == "resolved" else 'startsAt')
                if alert_time:
                    try:
                        # 处理ISO8601格式时间
                        if 'Z' in alert_time:
                            alert_time = alert_time.replace('Z', '+00:00')

                        dt = datetime.fromisoformat(alert_time)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)

                        # 转换为本地时区（更安全的方式）
                        local_tz = pytz.timezone('Asia/Shanghai')
                        alert_time = dt.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
                    except (ValueError, OSError) as e:
                        logger.warning(f"时间格式转换错误: {str(e)}，使用原始时间")
                        alert_time = alert_time.split('.')[0]  # 去除毫秒部分
                else:
                    alert_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                alert_info = {
                    "alert_name": alert_name,
                    "status": status,
                    "severity": severity,
                    "starts_at": alert_time,
                    "description": annotations.get('description', '无描述'),
                    "summary": annotations.get('summary', '无摘要'),
                    "labels": labels,
                    "annotations": annotations
                }

                grouped[alert_name].append(alert_info)

                stats_service.update({'by_status': {status: 1}})
                stats_service.update({'by_severity': {severity: 1}})
                stats_service.update({'by_alertname': {alert_name: 1}})

                if severity == "critical" and status == "firing":
                    logger.warning(f"严重告警: {alert_name} - {alert_info['summary']}")
            else:
                stats_service.update('dedup_alerts')

        return grouped


# 消息发送服务
class WeChatSender:
    @staticmethod
    def format_alert_message(alert: Dict) -> str:
        """格式化单个告警信息（修复时间显示问题）"""
        labels = alert.get('labels', {})
        annotations = alert.get('annotations', {})
        status = alert.get('status', 'unknown')

        # 获取必要字段
        pod_name = labels.get('pod', labels.get('pod_name', 'null'))
        namespace = labels.get('namespace', 'null')
        message = annotations.get('message', annotations.get('description', '无详情'))

        # 确定状态和颜色
        status_zh = '报警' if status == 'firing' else '恢复'
        color = 'red' if status == 'firing' else 'green'

        # 构建标题
        title = f"【<font color=\"{color}\">{status_zh}</font>】 {labels.get('alertname', '未知告警')} "
        title += "有新的报警信息" if status == 'firing' else "有报警恢复信息"

        # 构建消息内容
        content_parts = [
            f"## {title}",
            f">**服务位置**: {labels.get('job', '未知')}",
            f">**告警级别**: {labels.get('severity', 'unknown')}",
            f">**告警类型**: {labels.get('alertname', '未知类型')}",
            f">**告警主机**: {labels.get('instance', '未知IP')}",
            f">**告警详情**: {message}",
            f">**告警状态**: {status}"
        ]

        # 处理时间信息（更健壮的方式）
        starts_at = alert.get('startsAt')
        if starts_at:
            try:
                if 'Z' in starts_at:
                    starts_at = starts_at.replace('Z', '+00:00')
                dt = datetime.fromisoformat(starts_at.split('.')[0])  # 去除毫秒部分
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                local_tz = pytz.timezone('Asia/Shanghai')
                starts_at = dt.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
                content_parts.append(f">**触发时间**: {starts_at}")
            except (ValueError, OSError) as e:
                logger.warning(f"开始时间格式转换错误: {str(e)}")
                content_parts.append(f">**触发时间**: {starts_at.split('.')[0]}")
        else:
            content_parts.append(f">**触发时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # 如果是恢复状态，添加结束时间
        if status == 'resolved':
            ends_at = alert.get('endsAt')
            if ends_at:
                try:
                    if 'Z' in ends_at:
                        ends_at = ends_at.replace('Z', '+00:00')
                    dt = datetime.fromisoformat(ends_at.split('.')[0])  # 去除毫秒部分
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    local_tz = pytz.timezone('Asia/Shanghai')
                    ends_at = dt.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
                    content_parts.append(f">**触发结束时间**: {ends_at}")
                except (ValueError, OSError) as e:
                    logger.warning(f"结束时间格式转换错误: {str(e)}")
                    content_parts.append(f">**触发结束时间**: {ends_at.split('.')[0]}")

        return "\n".join(content_parts)

    @staticmethod
    def send_message(grouped_alerts: DefaultDict[str, List]) -> bool:
        if not circuit_breaker.check_state():
            stats_service.update('circuit_breaker_blocked')
            return False

        try:
            if not rate_limiter.is_allowed():
                logger.warning("已达到企业微信消息发送频率限制，将延迟发送")
                time.sleep(5)
                if not rate_limiter.is_allowed():
                    logger.error("仍然超出频率限制，消息发送失败")
                    stats_service.update('rate_limited')
                    circuit_breaker.record_failure()
                    return False

            total_alerts = sum(len(v) for v in grouped_alerts.values())
            if total_alerts > 10:
                return WeChatSender._send_bulk_message(grouped_alerts)

            success_count = 0
            fail_count = 0

            for alert_name, alerts in grouped_alerts.items():
                # 构建合并消息
                status = "firing" if any(a["status"] == "firing" for a in alerts) else "resolved"
                message_parts = [f"## 告警通知 - {alert_name} (共 {len(alerts)} 条相关告警)"]

                for idx, alert in enumerate(alerts, 1):
                    message_parts.append(f"\n---\n{idx}. {WeChatSender.format_alert_message(alert)}")

                message = "\n".join(message_parts)

                # 发送逻辑
                retries = 3
                success = False
                for attempt in range(retries):
                    try:
                        response = requests.post(
                            WECHAT_WEBHOOK_URL,
                            json={
                                "msgtype": "markdown",
                                "markdown": {
                                    "content": message,
                                    "mentioned_list": ["@all"] if status == "firing" else []
                                }
                            },
                            headers={"Content-Type": "application/json"},
                            timeout=10
                        )

                        if response.status_code == 200:
                            success = True
                            success_count += len(alerts)
                            break
                        else:
                            logger.error(f"发送失败(尝试 {attempt + 1}/{retries}): {response.text}")
                            if attempt < retries - 1:
                                time.sleep(2 ** attempt)
                    except Exception as e:
                        logger.error(f"发送异常(尝试 {attempt + 1}/{retries}): {str(e)}")
                        if attempt < retries - 1:
                            time.sleep(2 ** attempt)

                if not success:
                    fail_count += len(alerts)
                    circuit_breaker.record_failure()
                else:
                    circuit_breaker.record_success()

            stats_service.update('total_sent', success_count)
            stats_service.update('total_failed', fail_count)

            return success_count > 0

        except Exception as e:
            logger.error(f"异步发送消息错误: {str(e)}", exc_info=True)
            circuit_breaker.record_failure()
            return False

    @staticmethod
    def _send_bulk_message(grouped_alerts: DefaultDict[str, List]) -> bool:
        """批量发送格式化后的告警信息"""
        message_parts = ["## 批量告警通知\n"]
        alert_count = 0

        for alert_name, alerts in grouped_alerts.items():
            has_firing = any(a["status"] == "firing" for a in alerts)
            status = "firing" if has_firing else "resolved"
            status_zh = "报警" if status == "firing" else "恢复"
            color = "red" if status == "firing" else "green"

            message_parts.append(f"### 【<font color=\"{color}\">{status_zh}</font>】 {alert_name} ({len(alerts)}个)")

            # 只显示第一条告警的详细信息作为示例
            if alerts:
                message_parts.append(WeChatSender.format_alert_message(alerts[0]))

            message_parts.append("---")
            alert_count += len(alerts)

        message = "\n".join(message_parts)

        try:
            response = requests.post(
                WECHAT_WEBHOOK_URL,
                json={
                    "msgtype": "markdown",
                    "markdown": {
                        "content": message,
                        "mentioned_list": ["@all"] if any(
                            a["status"] == "firing" and
                            a.get('labels', {}).get('severity') in ["critical", "warning"]
                            for alerts in grouped_alerts.values()
                            for a in alerts
                        ) else []
                    }
                },
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"批量发送成功，共合并了 {alert_count} 个告警")
                stats_service.update('total_sent', alert_count)
                circuit_breaker.record_success()
                return True

            logger.error(f"批量发送失败: {response.text}")
            stats_service.update('total_failed', alert_count)
            circuit_breaker.record_failure()
            return False
        except Exception as e:
            logger.error(f"批量发送异常: {str(e)}")
            stats_service.update('total_failed', alert_count)
            circuit_breaker.record_failure()
            return False


# 队列处理器
def process_alert_queue():
    while True:
        try:
            batch_alerts = []
            try:
                while len(batch_alerts) < BATCH_SIZE:
                    batch_alerts.append(ALERT_QUEUE.get_nowait())
            except queue.Empty:
                pass

            if batch_alerts:
                grouped = AlertProcessor.process_and_group(batch_alerts)
                WeChatSender.send_message(grouped)
                stats_service.update('total_processed', len(batch_alerts))

                for _ in batch_alerts:
                    ALERT_QUEUE.task_done()

            time.sleep(1)

        except Exception as e:
            logger.error(f"处理告警队列错误: {str(e)}", exc_info=True)
            time.sleep(5)


# Flask路由
@app.route('/alert', methods=['POST'])
def handle_alert():
    try:
        data = request.get_json()

        if not data:
            logger.error("未接收到有效数据")
            return jsonify({"status": "error", "message": "无效的数据"}), 400

        alerts = data.get('alerts', [])

        if not alerts:
            logger.warning("未找到告警信息")
            return jsonify({"status": "warning", "message": "未找到告警信息"}), 200

        stats_service.update('total_received', len(alerts))

        queued = 0
        for alert in alerts:
            try:
                ALERT_QUEUE.put(alert, block=False)
                queued += 1
            except queue.Full:
                logger.error("告警队列已满，丢弃部分告警")
                stats_service.update('queue_overflow', len(alerts) - queued)
                break

        return jsonify({
            "status": "success",
            "message": f"已接收 {len(alerts)} 个告警，成功加入队列 {queued} 个",
            "received_count": len(alerts),
            "queued_count": queued,
            "queue_size": ALERT_QUEUE.qsize()
        }), 200

    except Exception as e:
        logger.error(f"处理告警请求错误: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    stats_data = stats_service.get_stats()

    uptime_seconds = int(time.time() - stats_data['start_time'])
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime = f"{hours}h {minutes}m {seconds}s"

    total_attempted = stats_data['total_sent'] + stats_data['total_failed']
    success_rate = 0 if total_attempted == 0 else round((stats_data['total_sent'] / total_attempted) * 100, 2)

    response_data = {
        "service_info": {
            "uptime": uptime,
            "current_queue_size": ALERT_QUEUE.qsize(),
            "max_queue_size": QUEUE_MAXSIZE,
            "worker_count": MAX_WORKERS,
            "batch_size": BATCH_SIZE,
            "rate_limit": f"{RATE_LIMIT}/{RATE_WINDOW}s"
        },
        "summary": {
            "total_received": stats_data['total_received'],
            "total_processed": stats_data['total_processed'],
            "total_sent": stats_data['total_sent'],
            "total_failed": stats_data['total_failed'],
            "success_rate": f"{success_rate}%",
            "rate_limited": stats_data['rate_limited'],
            "queue_overflow": stats_data['queue_overflow'],
            "dedup_alerts": stats_data['dedup_alerts'],
            "circuit_breaker_blocked": stats_data['circuit_breaker_blocked']
        },
        "by_status": dict(stats_data['by_status']),
        "by_severity": dict(stats_data['by_severity']),
        "top_alert_names": sorted(
            stats_data['by_alertname'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
    }

    return jsonify(response_data), 200


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "alertmanager-webhook",
        "queue_size": ALERT_QUEUE.qsize(),
        "queue_capacity": QUEUE_MAXSIZE,
        "workers": MAX_WORKERS,
        "uptime": f"{int(time.time() - stats_service.get_stats()['start_time'])} seconds"
    }), 200


if __name__ == '__main__':
    # 启动告警处理线程
    threading.Thread(target=process_alert_queue, daemon=True).start()

    # 启动Flask服务
    app.run(
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        threaded=True
    )
