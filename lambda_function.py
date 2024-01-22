import json
import logging
import os
import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler

BOT_TOKEN=os.environ['SLACK_BOT_TOKEN']

app = App(
    token=BOT_TOKEN,
    signing_secret=os.environ['SIGNING_SECRET'],
    process_before_response=True
)

handler = SlackRequestHandler(app)
dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('inha-pumpkin-coach')

SlackRequestHandler.clear_all_log_handlers()
logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)


@app.message("!도움")
def help(say):
    say(
        {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": ":jack_o_lantern: Pumpkin :jack_o_lantern: 도움말"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "*!하루매칭대기* 현재 대화할 수 있는 상대를 찾습니다.\n*!하루매칭종료* 현재 대화중인 상대가 있다면 대화를 종료합니다.\n*!도움* Pumpkin의 도움말을 보여줍니다.\n"
                        }
                    ]
                }
            ]
        }
    )


@app.message("!하루매칭대기")
def enter_request(message, say):
    team = message['team']
    PK = f'one#{team}'
    SK = message['user']
    query = {
        "FilterExpression": Attr('SK').eq(SK)
    }
    response = table.scan(**query)
    if response['Count'] == 0:
        item = {'PK': PK, 'SK': SK, 'partner': 'null'}

        say(
            {
                "blocks": [
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":new: *당신은 멘토인가요?*"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "예"
                                },
                                "style": "primary",
                                "value": "mentor",
                                "action_id": "mentor"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "아니오"
                                },
                                "style": "danger",
                                "value": "not_mentor",
                                "action_id": "not_mentor"
                            }
                        ]
                    }
                ]
            }
        )
    else:
        say("이미 매칭대기열에 있습니다! 내일을 기대하세요:)")


@app.action("mentor")
def handle_match_yes(ack, body, say, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    
    say(
        {
            "type": "modal",
	        "blocks": [
		        {
		            "type": "input",
		            "block_id": "input_block",
		            "element": {
		                "type": "plain_text_input",
		                "action_id": "password_input"
		            },
		            "label": {
		                "type": "plain_text",
		                "text": "비밀번호를 입력하세요."
		            }
		        },
		        {
                  "type": "actions",
                  "block_id": "submit_button_block",
                  "elements": [
                    {
                      "type": "button",
                      "text": {
                        "type": "plain_text",
                        "text": "제출"
                      },
                      "action_id": "check_password"
                    }
                  ]
                }
            ]
        }
    )

    
# 모달에서 전달된 입력값 확인 및 처리
@app.action("check_password")
def check_password(ack, body, say, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    
    password_input = body["state"]["values"]["input_block"]["password_input"]["value"]


    if password_input == os.environ['MENTOR_PASSWORD']:
        team = body["team"]["id"]
        user_id = body["user"]["id"]
        PK = f'one#{team}'
        SK = user_id
        
        item = {'PK': PK, 'SK': SK, 'partner': 'null', 'isMentor': 'true'}
        table.put_item(Item=item)
        say("매칭대기가 완료되었습니다 멘토님!! 매칭은 다음날부터 이뤄집니다.")
        
    else:
        say("비밀번호가 일치하지 않습니다. 매칭을 종료합니다.")


@app.action("not_mentor")
def handle_match_no(ack, body, say, client):
    ack()
    
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    
    team = body["team"]["id"]
    user_id = body["user"]["id"]
    PK = f'one#{team}'
    SK = user_id

    item = {'PK': PK, 'SK': SK, 'partner': 'null', 'isMentor': 'false'}
    table.put_item(Item=item)
    say("매칭대기가 완료되었습니다! 매칭은 다음날부터 이뤄집니다.")


@app.message("!하루매칭종료")
def stop_matching(message, say):
    team = message['team']
    PK = f'one#{team}'
    SK = message['user']
    query = {
        "FilterExpression": Attr('partner').eq(SK) | Attr('partner').eq("null")
    }
    response = table.scan(**query)

    if response['Items'] and response['Items'][0]['partner'] == "null":
        table.delete_item(Key={'PK': PK, 'SK': SK})
        say("대화를 종료하셨습니다. 자동으로 매칭 대기열에서도 제외되었습니다.")
    else:
        table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['SK']},
                    AttributeUpdates={'partner': {'Value': "null", 'Action': 'PUT'}})
        response = table.delete_item(Key={'PK': PK, 'SK': SK})
        say("대화를 종료하셨습니다. 자동으로 매칭 대기열에서도 제외되며 다시 대화하고 싶으시면 '!하루매칭대기' Command를 사용하세요.")


@app.message()
def chat_message(message, say):
    my_id = message['user']
    SK = message['user']
    query = {
        "FilterExpression": Attr('SK').eq(SK)
    }
    response = table.scan(**query)
    if response['Count'] == 0:
        say("참가를 원하시면 '!하루매칭대기' Command를 사용하세요. 매칭은 현재 시간 기준으로 다음 날 이뤄집니다.")
    else:
        partner_info = response['Items'][0]['partner']
        if partner_info == "null":
            say("매칭되어있는 상대가 없습니다ㅜ0ㅜ ")
        else:
            text = message["text"]
            say(text, channel=partner_info)


def lambda_handler(event, context):
    return handler.handle(event, context)
