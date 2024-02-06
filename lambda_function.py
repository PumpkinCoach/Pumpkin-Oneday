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

@app.action("console_action_button") # 버튼 누를 시 콘솔 표시
def console_action_button(ack, say, client, body):
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    body["user_id"] = body["user"]["id"]
    print_console(ack,client,body)

@app.command("/호박마차-하루")
def print_console(ack, client, body):
    ack()
    print(body)
    client.chat_postMessage(token=BOT_TOKEN, channel=body['user_id'],
    blocks= '''
            [
        		{
        			"type": "header",
        			"text": {
        				"type": "plain_text",
        				"text": ":jack_o_lantern: Pumpkin-Topic :jack_o_lantern:"
        			}
        		},
        		{
        			"type": "divider"
        		},
        		{
        			"type": "section",
        			"text": {
        				"type": "mrkdwn",
        				"text": "하루채팅 매칭대기열에 참가합니다. 매칭은 매일 자정에 자동으로 진행됩니다."
        			},
        			"accessory": {
        				"type": "button",
        				"text": {
        					"type": "plain_text",
        					"text": "하루매칭대기"
        				},
        				"value": "register_match",
        				"action_id": "register_match"
        			}
        		},
        		{
        			"type": "section",
        			"text": {
        				"type": "mrkdwn",
        				"text": "하루매칭을 종료합니다. 매칭대기열에서 제외됩니다."
        			},
        			"accessory": {
        				"type": "button",
        				"text": {
        					"type": "plain_text",
        					"text": "하루매칭종료"
        				},
        				"value": "quit_match",
        				"action_id": "quit_match"
        			}
        		},
        		{
        			"type": "section",
        			"text": {
        				"type": "mrkdwn",
        				"text": "GPT에게 질문합니다."
        			},
        			"accessory": {
        				"type": "button",
        				"text": {
        					"type": "plain_text",
        					"text": "GPT"
        				},
        				"value": "gpt_action_button",
        				"action_id": "gpt_action_button"
        			}
        		},
        		{
        			"type": "section",
        			"text": {
        				"type": "mrkdwn",
        				"text": "대화를 종료합니다."
        			},
        			"accessory": {
        				"type": "button",
        				"text": {
        					"type": "plain_text",
        					"text": "대화종료"
        				},
        				"value": "exit_chat",
        				"action_id": "exit_chat"
        			}
        		},
        		{
        			"type": "section",
        			"text": {
        				"type": "mrkdwn",
        				"text": "현재 하루채팅에 참가하고 있는 멘토들의 수를 알려줍니다."
        			},
        			"accessory": {
        				"type": "button",
        				"text": {
        					"type": "plain_text",
        					"text": "멘토비율"
        				},
        				"value": "mentor_number",
        				"action_id": "mentor_number"
        			}
        		}
	        ]
	        '''
    )


# 매칭대기열 등록
@app.action("register_match")
def enter_request(ack, say, body, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    team = body['user']['team_id']
    
    PK = f'one#{team}'
    SK = body['user']['id']
    
    query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('SK').eq(SK)
    }
    
    response = table.scan(**query)
    if response['Count'] == 0 or response['Items'][0]['inQueue'] == 'false':
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
        say("당신은 이미 매칭대기열에 있습니다! 내일을 기대하세요:)")
    return


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
    return

    
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
        query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('SK').eq(SK)
        }
        response = table.scan(**query)
        
        if response['Count'] != 0 and response['Items'][0]['inQueue'] == 'false':
            table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['SK']},
                    AttributeUpdates={'inQueue': {'Value': "true", 'Action': 'PUT'}, 'isMentor': {'Value': 'true', 'Action': 'PUT'}})
        else:
            item = {'PK': PK, 'SK': SK, 'partner': 'null', 'isMentor': 'true', 'inQueue': 'true'}
            table.put_item(Item=item)
        say("매칭대기가 완료되었습니다 멘토님!! 매칭은 다음날부터 이뤄집니다.")
        
    else:
        say("비밀번호가 일치하지 않습니다. 매칭을 종료합니다.")
    return

@app.action("not_mentor")
def handle_match_no(ack, body, say, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    team = body['user']['team_id']
    
    PK = f'one#{team}'
    SK = body['user']['id']
    query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('SK').eq(SK)
    }
    response = table.scan(**query)

    if response['Count'] != 0 and response['Items'][0]['inQueue'] == 'false':
            table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['SK']},
                    AttributeUpdates={'inQueue': {'Value': "true", 'Action': 'PUT'}})
    else:
        item = {'PK': PK, 'SK': SK, 'partner': 'null', 'isMentor': 'false', 'inQueue': 'true'}
        table.put_item(Item=item)
    say("매칭대기가 완료되었습니다! 매칭은 다음날부터 이뤄집니다.")
    return

@app.action("quit_match")
def stop_matching(ack, message, say, body, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    
    team = body['user']['team_id']
    PK = f'one#{team}'
    SK = body['user']['id']
    query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('SK').eq(SK)
    }
    response = table.scan(**query)
    
    if response['Count'] == 0 or response['Items'][0]['inQueue'] == "false" :
        say("당신은 현재 매칭대기열에 없습니다.")
    elif response['Items'] and response['Items'][0]['partner'] == "null":
        table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['SK']},
                    AttributeUpdates={'inQueue': {'Value': "false", 'Action': 'PUT'}})
        say("매칭을 종료하셨습니다. 당신은 매칭 대기열에서 제외됩니다.")
        
    else:
        table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['SK']},
                    AttributeUpdates={'inQueue': {'Value': "false", 'Action': 'PUT'}})
        say("매칭을 종료하셨습니다. 대화를 종료하고 싶으시면 /호박마차-하루 -> [대화종료]를 클릭하세요.")
    return
    
    
@app.action("exit_chat")
def stop_chat(ack, say, body, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    team = body['user']['team_id']
    
    PK = f'one#{team}'
    SK = body['user']['id']
    
    query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('SK').eq(SK)
    }
    response = table.scan(**query)
    
    if response['Count'] == 0:
        say("현재 대화 중인 상대가 없습니다. 매칭대기열에 참가하고 싶으시면 /호박마차-하루 -> [하루매칭대기]를 클릭하세요.")
        
    elif response['Items'][0]['partner'] == "null" :
        say("현재 대화 중인 상대가 없습니다. 매칭은 자정 12시에 자동으로 진행됩니다.")
    else:
        table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['SK']},
                    AttributeUpdates={'partner': {'Value': "null", 'Action': 'PUT'}})
        
        table.update_item(Key={'PK': PK, 'SK': response['Items'][0]['partner']},
                    AttributeUpdates={'partner': {'Value': "null", 'Action': 'PUT'}})
        
        say("대화를 종료하셨습니다. 매칭을 종료하고 싶으시면 /호박마차-하루 -> [하루매칭종료]를 클릭하세요.")
    return

@app.action("mentor_number")
def mentor_number(ack, say, body, client):
    ack()
    channel = body["channel"]["id"]
    join_action_button_modal_ts = body["message"]["ts"]
    client.chat_delete(token=BOT_TOKEN, channel=channel, ts=join_action_button_modal_ts)
    team = body['user']['team_id']
    
    PK = f'one#{team}'
    SK = body['user']['id']
    
    query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('isMentor').eq("true") & Attr('inQueue').eq("true")
    }
    response = table.scan(**query)
    num = response['Count']
    say(f'현재 참여 중인 멘토는 {num}명 입니다.')
    
    return

@app.message()
def chat_message(message, say):
    team = message['team']
    PK = f'one#{team}'
    SK = message['user']
    
    query = {
        "FilterExpression": Attr('PK').eq(PK) & Attr('SK').eq(SK)
    }
    response = table.scan(**query)
    
    if response['Count'] == 0:
        say("참가를 원하시면 /호박마차-하루 Command -> [하루매칭대기]를 클릭하세요. 매칭은 현재 시간 기준으로 다음 날 이뤄집니다.")
    else:
        partner_info = response['Items'][0]['partner']
        if partner_info == "null":
            say("매칭되어있는 상대가 없습니다ㅜ0ㅜ ")
        else:
            text = message["text"]
            say(text, channel=partner_info)
        

def lambda_handler(event, context):
    return handler.handle(event, context)
