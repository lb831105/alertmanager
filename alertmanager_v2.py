from flask import Flask, request, jsonify
import logging
import json
import requests
from datetime import datetime, timezone
from collections import defaultdict, deque
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import queue
import math
import os
from typing import Dict, List, DefaultDict, Deque

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

# 性能优化配置
ALERT_QUEUE = queue.Queue(maxsize=QUEUE_MAXSIZE)
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)


# 频率控制配置
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
            'start_time': time.time()
        }

    def update(self, counter: str or Dict[str, int], value: int = 1) -> None:
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
                    else:
                        logger.warning(f"Unknown stats key: {key}")

    def get_stats(self) -> Dict:
        with self.lock:
            return self.data.copy()


stats_service = StatsService()


# 告警处理器
class AlertProcessor:
    @staticmethod
    def process_and_group(alerts: List[Dict]) -> DefaultDict[str, List]:
        grouped = defaultdict(list)

        for alert in alerts:
            labels = alert.get('labels', {})
            annotations = alert.get('annotations', {})

            alert_name = labels.get('alertname', '未知告警')
            status = alert.get('status', 'unknown')
            severity = labels.get('severity', 'unknown')

            alert_time = alert.get('endsAt' if status == "resolved" else 'startsAt')
            if alert_time:
                try:
                    dt = datetime.fromisoformat(alert_time.replace('Z', '+00:00'))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    alert_time = dt.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
                except ValueError:
                    alert_time = "时间解析错误"
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

            # 更新统计
            stats_service.update({'by_status': {status: 1}})
            stats_service.update({'by_severity': {severity: 1}})
            stats_service.update({'by_alertname': {alert_name: 1}})

            if severity == "critical" and status == "firing":
                logger.warning(f"严重告警: {alert_name} - {alert_info['summary']}")

        return grouped


# 消息发送服务
class WeChatSender:
    @staticmethod
    def send_message(grouped_alerts: DefaultDict[str, List]) -> bool:
        try:
            if not rate_limiter.is_allowed():
                logger.warning("已达到企业微信消息发送频率限制，将延迟发送")
                time.sleep(5)
                if not rate_limiter.is_allowed():
                    logger.error("仍然超出频率限制，消息发送失败")
                    stats_service.update('rate_limited')
                    return False

            success_count = 0
            fail_count = 0

            for alert_name, alerts in grouped_alerts.items():
                has_firing = any(alert["status"] == "firing" for alert in alerts)
                status = "firing" if has_firing else "resolved"
                status_text = "故障告警" if status == "firing" else "故障恢复"

                status_color_map = {
                    "firing": {"critical": "warning", "warning": "warning", "info": "info"},
                    "resolved": {"critical": "comment", "warning": "comment", "info": "comment"}
                }

                message_parts = [
                    f"## {status_text} - {alert_name}\n",
                    f"> **告警数量**: {len(alerts)}",
                    f"> **状态**: {status}",
                    "\n---\n"
                ]

                for idx, alert in enumerate(alerts, 1):
                    severity = alert["severity"]
                    color_type = status_color_map.get(status, {}).get(severity, "comment")

                    message_parts.extend([
                        f"### {idx}. <font color=\"{color_type}\">{severity.upper()}</font>",
                        f"- **时间**: {alert['starts_at']}",
                        f"- **摘要**: {alert['summary']}",
                        f"- **描述**: {alert['description']}",
                        "\n---\n"
                    ])

                message = "\n".join(message_parts)

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
                                    "mentioned_list": ["@all"] if status == "firing" and severity in ["critical",
                                                                                                      "warning"] else []
                                }
                            },
                            headers={"Content-Type": "application/json"},
                            timeout=10
                        )

                        if response.status_code == 200:
                            logger.info(f"发送成功，合并了 {len(alerts)} 个'{alert_name}'告警")
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
                    logger.error(f"所有重试均失败，'{alert_name}'告警发送失败")
                    fail_count += len(alerts)

            stats_service.update('total_sent', success_count)
            stats_service.update('total_failed', fail_count)

            return success_count > 0

        except Exception as e:
            logger.error(f"异步发送消息错误: {str(e)}", exc_info=True)
            return False


# 队列处理器
def process_alert_queue():
    """处理告警队列，批量合并告警"""
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
    """接收Alertmanager发送的告警，加入处理队列"""
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
    """获取告警统计信息"""
    stats_data = stats_service.get_stats()

    uptime_seconds = int(time.time() - stats_data['start_time'])
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime = f"{hours}h {minutes}m {seconds}s"

    total_attempted = stats_data['total_sent'] + stats_data['total_failed']
    success_rate = 0 if total_attempted == 0 else \
        round((stats_data['total_sent'] / total_attempted) * 100, 2)

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
            "queue_overflow": stats_data['queue_overflow']
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
    """健康检查接口，包含队列状态"""
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
