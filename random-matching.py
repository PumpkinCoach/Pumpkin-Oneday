import json
import logging
import os
import boto3
import random
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
from slack_sdk import WebClient

app = App(
    token=os.environ['SLACK_BOT_TOKEN'],
    signing_secret=os.environ['SIGNING_SECRET'],
    process_before_response=True
)
client = WebClient(token=os.environ['SLACK_BOT_TOKEN'])

handler = SlackRequestHandler(app)
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('inha-pumpkin-coach')

SlackRequestHandler.clear_all_log_handlers()
logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)


    
def lambda_handler(event, context):
    PK = 'one#T04VBKA4L4Q'
    
    query = {
        "FilterExpression": Attr('PK').eq(PK)
    }
    
    response = table.scan(**query)
    
    size =int(response['Count'])
    random_number = -1
    if size % 2 == 1:
        random_number= random.randint(0, size-1)

    index=[num for num in range(0, size) if num != random_number]
    mid = len(index) // 2
    
    first_half = index[:mid]
    second_half = index[mid:]
    random.shuffle(second_half)
    
    for i in range(len(first_half)):
        SK=response['Items'][first_half[i]]['SK']
        partner=response['Items'][second_half[i]]['SK']
        table.update_item(Key={'PK':PK,'SK':SK}, AttributeUpdates={'partner': {'Value': partner, 'Action':'PUT'}})
        table.update_item(Key={'PK':PK,'SK':partner}, AttributeUpdates={'partner': {'Value': SK, 'Action':'PUT'}})
    
    if random_number != -1:
        SK = response['Items'][random_number]['SK']
        table.update_item(Key={'PK':PK,'SK':SK}, AttributeUpdates={'partner': {'Value': "U05S42UH483", 'Action':'PUT'}})
    
    for i in range(size):
        result = client.chat_postMessage(
            channel=response['Items'][i]['SK'], 
            text="🧨🧨Boom!!! 방이 터지고 새로운 상대가 매칭되었습니다!!🧨🧨"
        )
    
    return handler.handle(event, context)
