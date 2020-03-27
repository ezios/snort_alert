#coding utf-8
import time
import events
import pickle
import os
import string
from gmail import create_message,send_message
from info import mail_from,mail_to,level


def send_alert(message_text,subject):
    for to in mail_to:    
        message = create_message(mail_from,to,subject,message_text)
        send_message("me", message)



def strings(payload):
    binpayload = bytearray.fromhex(payload)
    result=""
    for c  in binpayload:
        str_c = chr(c)
        if str_c in string.printable[0:95]:
            result += str_c
    return result

def getoldevents():
    if os.path.exists('previous.pickle'):
            with open('previous.pickle', 'rb') as f:
                old_events = pickle.load(f)
                return old_events
    return None

previous = getoldevents()
if not previous:
    previous = [600]
print("Entring Loop")
while True:
    alerts = events.data(events.LastEvent() - previous[-1],level)
    print("Looking For Data")
    for alert in alerts:
        if all(alert["EventId"] >= i for i in previous):
            if alert["Payload"]!= 0:
                PayloadStrings = strings(alert["Payload"])
            else:
                alert["Payload"] = "Vide"
                PayloadStrings = "Vide"

            message = """ID :  {} 
    Temps : {} 
    Signature Alerte : {} 
    Reference évenement : {}
    Description : {} 
    Protocole réseau : {}
    Adresse source et port source : {} : {} 
    Adresse destination et port de destianation : {} : {} 
    Contenu du paquet : 
         Hexadecimal : {}   
         Ascii :  {} \n\n """.format(alert["EventId"],\
                alert["EventTimeStamp"],\
                alert["Alert"],\
                alert["ref"],
                alert["AlertClass"],\
                alert["Protocol"],
                alert["SourceIP"],alert["SourcePort"],\
                alert["DestinationIP"],alert["DestinationPort"],\
                alert["Payload"][1:40],\
                PayloadStrings)
            if alert["Priority"] == 0:
                subject= "Alerte Niveau Elevée"
            if alert["Priority"] == 1:
                subject= "Alerte Niveau Information"
            if alert["Priority"] == 2:
                subject= "Protocole non respecté"
            previous.append (alert["EventId"])
            with open('previous.pickle',"wb") as p:
                pickle.dump(previous,p)
            send_alert(message,subject)
        time.sleep(60)  
        print("sleeping...")             

                      