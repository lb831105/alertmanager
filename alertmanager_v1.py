from flask import Flask, request, jsonify
import logging
import json
import requests
from datetime import datetime
from collections import defaultdict, deque
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import queue
import math

# 企业微信机器人Webhook地址
WECHAT_WEBHOOK_URL = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=你的机器人key"

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("alert_webhook.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 性能优化和频率控制配置
MAX_WORKERS = 4
ALERT_QUEUE = queue.Queue(maxsize=1000)
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# 企业微信发送频率控制
WECHAT_RATE_LIMIT = {
    'max_messages': 20,
    'time_window': 60,
    'message_timestamps': deque()
}
RATE_LIMIT_LOCK = threading.Lock()

# 统计数据
stats = {
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
STATS_LOCK = threading.Lock()


def update_stats(counter, value=1):
    """更新统计数据，修复字典类型处理逻辑"""
    with STATS_LOCK:
        if isinstance(counter, str):
            stats[counter] += value
        elif isinstance(counter, dict):
            for key, val in counter.items():
                if key in stats:
                    if isinstance(stats[key], defaultdict):
                        # 对于defaultdict，直接更新内部值
                        for sub_key, sub_val in val.items():
                            stats[key][sub_key] += sub_val
                    else:
                        stats[key] += val
                else:
                    logger.warning(f"统计数据中不存在键: {key}")
        else:
            logger.warning(f"不支持的统计数据类型: {type(counter)}")


def is_within_rate_limit():
    """检查是否在频率限制内"""
    with RATE_LIMIT_LOCK:
        now = time.time()
        while WECHAT_RATE_LIMIT['message_timestamps'] and \
                now - WECHAT_RATE_LIMIT['message_timestamps'][0] > WECHAT_RATE_LIMIT['time_window']:
            WECHAT_RATE_LIMIT['message_timestamps'].popleft()

        if len(WECHAT_RATE_LIMIT['message_timestamps']) < WECHAT_RATE_LIMIT['max_messages']:
            WECHAT_RATE_LIMIT['message_timestamps'].append(now)
            return True
        update_stats('rate_limited')
        return False


def send_wechat_message_async(grouped_alerts):
    """异步发送微信消息，带重试机制"""
    try:
        if not is_within_rate_limit():
            logger.warning("已达到企业微信消息发送频率限制，将延迟发送")
            time.sleep(5)
            if not is_within_rate_limit():
                logger.error("仍然超出频率限制，消息发送失败")
                return False

        success_count = 0
        fail_count = 0

        for alert_name, alerts in grouped_alerts.items():
            has_firing = any(alert["status"] == "firing" for alert in alerts)
            status = "firing" if has_firing else "resolved"
            status_text = "故障告警" if status == "firing" else "故障恢复"

            status_color_map = {
                "firing": {"critical": "red", "warning": "orange", "info": "green"},
                "resolved": {"critical": "gray", "warning": "gray", "info": "gray"}
            }

            message_parts = [f"**{status_text} - {alert_name}**"]
            message_parts.append(f"> 共 {len(alerts)} 个相关告警")

            for idx, alert in enumerate(alerts, 1):
                severity = alert["severity"]
                color = status_color_map.get(status, {}).get(severity, "gray")

                message_parts.extend([
                    f"> **{idx}. 级别**: <font color=\"{color}\">{severity.upper()}</font>",
                    f">    时间: {alert['starts_at']}",
                    f">    摘要: {alert['summary']}",
                    f">    描述: {alert['description']}",
                    "> ---"
                ])

            message = "\n".join(message_parts[:-1])

            retries = 3
            success = False
            for attempt in range(retries):
                try:
                    response = requests.post(
                        WECHAT_WEBHOOK_URL,
                        data=json.dumps({
                            "msgtype": "markdown",
                            "markdown": {"content": message}
                        }),
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

        update_stats('total_sent', success_count)
        update_stats('total_failed', fail_count)

        return success_count > 0

    except Exception as e:
        logger.error(f"异步发送消息错误: {str(e)}", exc_info=True)
        return False


def process_alert_queue():
    """处理告警队列，批量合并告警"""
    while True:
        try:
            batch_alerts = []
            try:
                while len(batch_alerts) < 50:
                    batch_alerts.append(ALERT_QUEUE.get_nowait())
            except queue.Empty:
                pass

            if batch_alerts:
                grouped = process_and_group_alerts(batch_alerts)
                send_wechat_message_async(grouped)
                update_stats('total_processed', len(batch_alerts))

                for _ in batch_alerts:
                    ALERT_QUEUE.task_done()

            time.sleep(1)

        except Exception as e:
            logger.error(f"处理告警队列错误: {str(e)}", exc_info=True)
            time.sleep(5)


def process_and_group_alerts(alerts):
    """处理告警并按告警名称分组"""
    grouped = defaultdict(list)

    for alert in alerts:
        alert_name = alert.get('labels', {}).get('alertname', '未知告警')
        status = alert.get('status', 'unknown')
        severity = alert.get('labels', {}).get('severity', 'unknown')

        alert_time = alert.get('endsAt' if status == "resolved" else 'startsAt',
                               datetime.utcnow().isoformat())

        alert_info = {
            "alert_name": alert_name,
            "status": status,
            "severity": severity,
            "starts_at": alert_time,
            "description": alert.get('annotations', {}).get('description', '无描述'),
            "summary": alert.get('annotations', {}).get('summary', '无摘要'),
            "labels": alert.get('labels', {}),
            "annotations": alert.get('annotations', {})
        }

        grouped[alert_name].append(alert_info)

        update_stats({'by_status': {status: 1}})
        update_stats({'by_severity': {severity: 1}})
        update_stats({'by_alertname': {alert_name: 1}})

        if severity == "critical" and status == "firing":
            logger.warning(f"严重告警: {alert_name} - {alert_info['summary']}")

    return grouped


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

        update_stats('total_received', len(alerts))

        queued = 0
        for alert in alerts:
            try:
                ALERT_QUEUE.put(alert, block=False)
                queued += 1
            except queue.Full:
                logger.error("告警队列已满，丢弃部分告警")
                update_stats('queue_overflow', len(alerts) - queued)
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
    with STATS_LOCK:
        uptime_seconds = int(time.time() - stats['start_time'])
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime = f"{hours}h {minutes}m {seconds}s"

        total_attempted = stats['total_sent'] + stats['total_failed']
        success_rate = 0 if total_attempted == 0 else \
            round((stats['total_sent'] / total_attempted) * 100, 2)

        stats_data = {
            "service_info": {
                "uptime": uptime,
                "current_queue_size": ALERT_QUEUE.qsize(),
                "max_queue_size": ALERT_QUEUE.maxsize,
                "worker_count": MAX_WORKERS
            },
            "summary": {
                "total_received": stats['total_received'],
                "total_processed": stats['total_processed'],
                "total_sent": stats['total_sent'],
                "total_failed": stats['total_failed'],
                "success_rate": f"{success_rate}%",
                "rate_limited": stats['rate_limited'],
                "queue_overflow": stats['queue_overflow']
            },
            "by_status": dict(stats['by_status']),
            "by_severity": dict(stats['by_severity']),
            "top_alert_names": sorted(
                stats['by_alertname'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }

        return jsonify(stats_data), 200


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口，包含队列状态"""
    return jsonify({
        "status": "healthy",
        "service": "alertmanager-webhook",
        "queue_size": ALERT_QUEUE.qsize(),
        "worker_count": MAX_WORKERS,
        "uptime": f"{int(time.time() - stats['start_time'])} seconds"
    }), 200


if __name__ == '__main__':
    threading.Thread(target=process_alert_queue, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
