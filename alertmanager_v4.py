from flask import Flask, request, jsonify
import os
import logging
import requests
from collections import defaultdict
from datetime import datetime, timezone
import pytz
import threading
import time
import queue

# 配置
WECHAT_WEBHOOK = os.getenv("WECHAT_WEBHOOK", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=2b870a61-c53b-4bac-a1a7-1f21ff5434b4")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
QUEUE_SIZE = int(os.getenv("QUEUE_SIZE", "1000"))
RATE_LIMIT = 20  # 每分钟限制

app = Flask(__name__)
alert_queue = queue.Queue(maxsize=QUEUE_SIZE)

# 日志配置
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlertProcessor:
    @staticmethod
    def format_time(iso_time: str) -> str:
        """简化时间格式化"""
        if not iso_time:
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            dt = datetime.fromisoformat(iso_time.replace('Z', '+00:00').split('.')[0])
            return dt.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return iso_time.split('.')[0]

    @staticmethod
    def process(alerts: list) -> dict:
        """优化后的告警处理"""
        groups = defaultdict(list)
        seen = set()

        for alert in alerts:
            labels = alert.get('labels', {})
            uid = (labels.get('alertname'), alert.get('status'))

            if uid not in seen:
                seen.add(uid)
                groups[labels.get('alertname')].append({
                    'name': labels.get('alertname', '未知告警'),
                    'status': alert.get('status'),
                    'severity': labels.get('severity'),
                    'time': AlertProcessor.format_time(alert.get('startsAt')),
                    'summary': alert.get('annotations', {}).get('summary', '无摘要'),
                    'labels': labels
                })
        return groups


class WeChatSender:
    @staticmethod
    def send(alerts: dict) -> bool:
        """简化消息发送"""
        try:
            for alert_name, alert_list in alerts.items():
                message = f"## {alert_name}告警\n"
                for alert in alert_list:
                    color = 'red' if alert['status'] == 'firing' else 'green'
                    message += f">**状态**: <font color=\"{color}\">{alert['status']}</font>\n"
                    message += f">**时间**: {alert['time']}\n"
                    message += f">**摘要**: {alert['summary']}\n---\n"

                requests.post(
                    WECHAT_WEBHOOK,
                    json={"msgtype": "markdown", "markdown": {"content": message}},
                    timeout=5
                )
            return True
        except Exception as e:
            logger.error(f"发送失败: {e}")
            return False


def process_queue():
    """队列处理线程"""
    while True:
        try:
            alerts = []
            while len(alerts) < 50 and not alert_queue.empty():
                alerts.append(alert_queue.get())

            if alerts:
                grouped = AlertProcessor.process(alerts)
                WeChatSender.send(grouped)

        except Exception as e:
            logger.error(f"队列处理错误: {e}")
            time.sleep(5)


@app.route('/alert', methods=['POST'])
def handle_alert():
    """API端点"""
    try:
        alerts = request.json.get('alerts', [])
        for alert in alerts:
            alert_queue.put(alert, block=False)
        return jsonify({"status": "success", "queued": len(alerts)}), 200
    except queue.Full:
        return jsonify({"status": "error", "message": "队列已满"}), 429
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "queue_size": alert_queue.qsize()
    }), 200


if __name__ == '__main__':
    threading.Thread(target=process_queue, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
