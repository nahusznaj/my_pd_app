from flask import Flask, request, make_response
import requests
import pprint
import time 
import hmac 
import hashlib
import urllib

from dotenv import load_dotenv
load_dotenv()

import os
PD_token = os.getenv("PD_token")
slack_signing_secret = os.getenv("slack_signing_secret")

app = Flask(__name__)

def obtain_schedule_ids():
    # poll PD to obtain a list with all the schedules.
    payload_schedules =  {'total':'true', 'limit':100}
    schedules_list = []

    rr = requests.get('https://api.pagerduty.com/schedules', headers = {"Authorization":'Token token='+PD_token},  params = payload_schedules)

    schedules_page_response = rr.json()

    all_schedules_list = schedules_page_response['schedules']

    for item in all_schedules_list:
        schedules_list.append(item['id'])

    return schedules_list 

schedules_id = obtain_schedule_ids() 

def verify_signature(headers, slack_payload, known_signature):
    timestamp = headers['X-Slack-Request-Timestamp'] # another var of absolute time in headers sent by Slack
    slack_signature = headers['X-Slack-Signature'] # this is the signature that Slack sends along the POST, in the headers.
    
    # this is the payload in the body of the request from Slack to our app when the slash command was executed in Slack
    dict_slack = slack_payload.to_dict() 

    incoming_payload = urllib.parse.urlencode(dict_slack)

    ### compose the message for our side's sha256 signature
    sig_basestring = 'v0:' + timestamp + ':' + incoming_payload
    sig_basestring = sig_basestring.encode('utf-8')

    ### Signing Secret provided by Slack upon creating the App, encoded:
    signing_secret = known_signature.encode('utf-8')
    
    ## create our signature
    my_signature = 'v0=' + hmac.new(signing_secret, sig_basestring, hashlib.sha256).hexdigest()

    if my_signature == slack_signature:  
        return True
    else:
        return False

def verify_user_text_input(slack_payload):
    dict_slack = slack_payload.to_dict() 
    user_text_input = dict_slack['text']  
    return user_text_input == ''

def obtain_oncalls_results(schedules_list):
    ## read the schedules for each scheduleID item 
    payload = {'time_zone':'America/Argentina/Buenos_Aires', 'total':'true', 'schedule_ids[]':schedules_list, 'limit':100} #scheduleIDs 
    r = requests.get('https://api.pagerduty.com/oncalls', headers = {"Authorization":'Token token='+PD_token},  params = payload)
    
    pager_response = r.json()
    
    ## create a dict with each schedule and the oncall user
    information_dict = {}
    for j in pager_response['oncalls']:
        if j['schedule']['summary'] not in information_dict:
            information_dict[j['schedule']['summary']] = j['user']['summary']

    information_dict = dict( sorted(information_dict.items(), key=lambda x: x[0].lower()) )

    output = '\n'.join("{}: {}".format(k, v) for k, v in information_dict.items()) # produce the text message for the response

    return output 

def verify_replay_attack(headers):
    timestamp = headers['X-Slack-Request-Timestamp'] #absolute time in headers sent by Slack

    ### Security measure ###
    # The request timestamp is more than five minutes from local time.
    # It could be a replay attack, so let's ignore it. Otherwise, the controller continues
    if timestamp is not None:
        timestamp = float(timestamp)
        if abs(time.time() - timestamp) > 60 * 5:
            return '', 403
        else:
            pass

@app.route('/', methods=['POST']) 
def all_schedules():
    ### Security measure ###
    # verify there's no replay attack
    verify_replay_attack(request.headers)
  

    ### Security measure ###
    # verify the signature, if successful this will be True
    signature_validation_result = verify_signature(request.headers, request.form, slack_signing_secret) 
    
    # ### Security measure ###
    # # verify no input text was passed, if successful this will be True
    input_text_verif_result = verify_user_text_input(request.form) 
    
    # if the signatures match and no text was passed, let's then run this show!
    if signature_validation_result and input_text_verif_result: 
        output = obtain_oncalls_results(schedules_id)
        response = make_response(output, 200)
        response.mimetype = "text/plain"
        return response
    elif signature_validation_result and not input_text_verif_result: 
        response = make_response('Error: Text input is not permitted', 200) # 200 response is required in order to offer a message to the user
        response.mimetype = "text/plain"
        return response
    elif not signature_validation_result: 
        response = make_response('', 403)
        response.mimetype = "text/plain"
        return response

if __name__ == "__main__":
    app.run(debug=True)
