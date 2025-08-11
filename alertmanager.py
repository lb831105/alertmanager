# -*- coding: utf-8 -*-
import os
import json
import requests
import arrow
from flask import Flask, request
import logging
from logging.handlers import TimedRotatingFileHandler  # 新增，用于按时间轮转日志文件

# 配置日志记录
logger = logging.getLogger(__name__)

app = Flask(__name__)


logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
datefmt = '%Y-%m-%d %H:%M:%S'

# 使用TimedRotatingFileHandler实现每天一个日志文件
file_handler = TimedRotatingFileHandler('webhook_server.log', when='midnight', interval=1, backupCount=7)
file_handler.suffix = '%Y-%m-%d.log'
file_handler.setFormatter(formatter)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)


def bytes2json(data_bytes):
    """
    将字节类型的数据转换为JSON格式

    参数:
    data_bytes (bytes): 字节类型的数据

    返回:
    dict: 解析后的JSON数据，如果转换失败返回None
    """
    try:
        data = data_bytes.decode('utf8').replace("'", '"')
        return json.loads(data)
    except UnicodeDecodeError as e:
        logger.error("UnicodeDecodeError occurred when decoding data: %s", e)
        return None
    except json.JSONDecodeError as e:
        logger.error("JSONDecodeError occurred when parsing data: %s", e)
        return None


def makealertdata(data):
    """
    根据传入的告警数据构造要发送的消息数据

    参数:
    data (dict): 包含告警信息的原始数据

    返回:
    dict: 构造好的适合发送的消息数据，如果构造过程出现问题返回None
    """
    if not data or 'alerts' not in data:
        logger.error("Invalid input data format for makealertdata function")
        return None
    send_data_list = []
    for output in data['alerts']:
        try:
            pod_name = output['labels'].get('pod', output['labels'].get('pod_name', 'null'))
            namespace = output['labels'].get('namespace', 'null')
            message = output['annotations'].get('message', output['annotations'].get('description', 'null'))
            status_zh = '报警' if output['status'] == 'firing' else '恢复'
            title = f"【{status_zh}】 {output['labels']['alertname']} {'有新的报警信息' if output['status'] == 'firing' else '有报警恢复信息'}"
            # 根据状态设置文字颜色的HTML标签，红色表示报警，绿色表示恢复
            color_tag = '<font color="red">报警</font>' if status_zh == '报警' else '<font color="green">恢复</font>'
            title = title.replace(status_zh, color_tag)
            content_parts = [
                f"## {title} ",
                f">**服务位置**: {output['labels']['job']} ",
                f">**告警级别**: {output['labels']['severity']} ",
                f">**告警类型**: {output['labels']['alertname']} ",
                f">**告警主机**: {output['labels']['instance']} ",
                f">**告警详情**: {message} ",
                f">**告警状态**: {output['status']} "
            ]
            if output['status'] == 'resolved':
                content_parts.append(f">**触发结束时间**: {arrow.get(output['endsAt']).to('Asia/Shanghai').format('YYYY-MM-DD HH:mm:ss ZZ')} ")
            content_parts.append(f">**触发时间**: {arrow.get(output['startsAt']).to('Asia/Shanghai').format('YYYY-MM-DD HH:mm:ss ZZ')} ")
            markdown_content = "\n\n".join(content_parts)
            send_data = {
                "msgtype": "markdown",
                "markdown": {
                    "content": markdown_content
                }
            }
            send_data_list.append(send_data)
        except KeyError as e:
            logger.error("KeyError occurred when processing alert data: %s", e)
            continue
        except arrow.parser.ParserError as e:
            logger.error("Arrow ParserError occurred when formatting time: %s", e)
            continue
    return send_data_list if send_data_list else None


def send_alert(data):
    """
    发送告警消息到企业微信机器人

    参数:
    data (dict or list): 要发送的消息数据，可以是单个消息字典或者多个消息字典组成的列表

    返回:
    bool: 如果发送成功返回True，否则返回False
    """
    token = os.getenv('ROBOT_TOKEN')
    if not token:
        logger.error("ROBOT_TOKEN environment variable not set")
        return False
    url = f'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={token}'
    if isinstance(data, dict):
        send_data_list = [data]
    elif isinstance(data, list):
        send_data_list = data
    else:
        logger.error("Invalid data format for sending alert. Expected dict or list")
        return False
    for send_data in send_data_list:
        try:
            req = requests.post(url, json=send_data)
            req.raise_for_status()
            result = req.json()
            if result['errcode']!= 0:
                logger.error("Notify enterprise wechat error: errcode=%s, errmsg=%s", result['errcode'], result['errmsg'])
                return False
        except requests.exceptions.RequestException as e:
            logger.error("RequestException occurred when sending alert: %s", e)
            return False
        except json.JSONDecodeError as e:
            logger.error("JSONDecodeError occurred when parsing response: %s", e)
            return False
    return True


@app.route('/', methods=['POST', 'GET'])
def send():
    """
    处理请求的路由函数，根据请求方法进行相应操作，POST请求时发送告警消息，GET请求返回欢迎信息
    """
    if request.method == 'POST':
        client_ip = request.remote_addr  # 获取请求客户端的IP地址
        logger.info(f"Received POST request from {client_ip}")
        post_data = request.get_data()
        json_data = bytes2json(post_data)
        if json_data:
            logger.info(f"Parsed JSON data from request: {json_data}")
            if send_alert(makealertdata(json_data)):
                logger.info(f"Successfully sent alert messages for request from {client_ip}")
                return 'success'
            else:
                logger.error(f"Failed to send alert messages for request from {client_ip}")
                return 'Failed to send alert messages'
        else:
            logger.error(f"Invalid data format in request from {client_ip}, unable to process")
            return 'Invalid data format, unable to process'
    else:
        client_ip = request.remote_addr
        logger.info(f"Received GET request from {client_ip}")
        return 'Welcome to use prometheus alertmanager dingtalk webhook server!'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)