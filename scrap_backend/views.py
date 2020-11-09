from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import JsonResponse
from django.core.paginator import Paginator
import json
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
import datetime

from django.contrib.auth.hashers import make_password, check_password
from .models import User, Refresh_Token, Product_Id, Failure_Cause, Scrap, Cache_Token


#########################
#Functions and var to be used by api's


pag_num = 10; #amount of pages for paginator
encoding_key = 'let us chang it to a random key maybe like 30 characters long? Would change for production versionssss'

def create_refresh_token( user_name):
    #save it associated with a user 


    user = User.objects.filter(username=user_name)
    if(len(user) == 0):
        return JsonResponse({'error': 'cannot get refresh token'}, status=409) #return conflict
        
    #double check you don't need to iterate
    #need to save encoded token as a hash. - i'll just use bcrypt 
    



    exp = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    payload = {
            "type": "refresh",
            "exp": exp,
        }
    encoded_token = jwt.encode(payload,  encoding_key, algorithm='HS256') 

    print(f'pre byte string conv: {encoded_token}')

    post_conv = str(encoded_token, 'utf-8')

    print(f'post byte string conv: {post_conv}')

    hashed_token = make_password(post_conv)

    refr = Refresh_Token(token=hashed_token, user=user[0])
    refr.save()
    id = refr.id

    return encoded_token, id


def validate_refresh_token(encoded_token, primary_key):
    
    
    try:
        
        decoded_key = jwt.decode(encoded_token, encoding_key, algorithms=['HS256'])

    except jwt.ExpiredSignatureError:

        return JsonResponse({'error ': 'expired refresh token'}, status=403)
    except:
        print('invalid signature!!')
        return False

    #check that the username matches the username in the DB
    #also check that it's not expired
    print('validating refresh token')

    ref = Refresh_Token.objects.get(pk=primary_key)
    print(ref)
    print(ref.token)
    print(f'our saved refresh token belonged to: {ref.user.username}')
    logged_token = ref.token

    is_same = check_password(encoded=logged_token, password=encoded_token)
    print(f'is_same is: {is_same}')

    
    if is_same:
        return True #i.e. the refresh token is correct.
    else:
        print('the refresh token didnt match what was in the database. Check order_by.')
        return False  


def create_token( user_name):
    payload = {
            "name": str(user_name),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
        }
    encoded_token = jwt.encode(payload,  encoding_key, algorithm='HS256') 

    #TODO add an expiration date into the encode func above {'exp': (datetime.utcnow() + datetime.timedelta(days = 1))},
    return encoded_token

def validate_token(encoded_token, user_name):
    comparison_message ={'name': str(user_name)} 
    
    try:
        
        decoded_key = jwt.decode(encoded_token, encoding_key, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error ': 'expired key'}, status=403)
    except:
        print('invalid signature mother fucker!!')
        return False
    
    decoded_name = decoded_key['name']
    comparison_name = comparison_message['name']
    print( f' decoded name: {decoded_name} ,  and comparison_message: {comparison_name}')

    
    
    if decoded_key['name'] == comparison_message['name']:
        return True #i.e. if the message is right return it's validated
    else:
        print('message is wrong for username')
        return False  



##########################################
#Starting API's
##########################################  




def open_scrap(request):
    #TODO: make this functional and return pagination data.
    if request.method == "GET":
        post = Post.objects.get(id=id)
        return JsonResponse({'text': f'{post.text}'})

def closed_scrap(request):
    #TODO: make this functional and return pagination data.
    if request.method == "GET":
        post = Post.objects.get(id=id)
        return JsonResponse({'text': f'{post.text}'})
    

def graph_data(request):
    #TODO: make this functional.
    if request.method == "GET":
        post = Post.objects.get(id=id)
        return JsonResponse({'text': f'{post.text}'})
    

def create_user(request):
    if request.method == 'POST':
        #make sure no user is already in the system with that username.


        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        #check if the user already has a password?
        user_id = body['username']
        password = body['password']
        checking_username = User.objects.filter(username=user_id)
        if len(checking_username) >0:
            return JsonResponse({'error': 'username taken.'}, status=409) #return conflict

        print(f'our sent password was: {password}')
        password = make_password(password)
        print(password)
        user = User(username=user_id, password=password )
        user.save()
        return JsonResponse({'text': f'{user_id}'})



def get_token(request):
    #lets set it up to return a token if refresh token is correct
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        #check if the user already has a password?
        ref_id = body['refreshTokenID']
        ref_token = body['refreshToken']
        db_ref_token = Refresh_Token.objects.get(id=ref_id)
        user = db_ref_token.user
        


        if(user != None and db_ref_token != None):
            same_password = check_password(encoded=db_ref_token.token, password=ref_token)
        else:
            same_password = False

        if same_password == True:
            token = create_token(user.username)
            print(f'our created and sent token was: {token}')
            return JsonResponse({'token': f'{token}'})
        else:
            return JsonResponse({'error': 'creditials incorrect'}, status=403)
        
def check_token(request):
    if request.method == 'POST':
        bearer = request.headers["Authorization"]
        bearer = bearer[7:]
        print( f'our recieved token was {bearer}')

        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        username = body['username']
        print(f'username: {username}')


        valid = validate_token(bearer, username)
        print(f'valid: {valid}')

        if valid == True:
            return JsonResponse({'token': 'is valid'})
        elif valid == False:
            return JsonResponse({'error': 'token invalid'}, status=403)
        else:
            return JsonResponse({'error': 'expired key'}, status=403)


def login(request):
    #i.e. get refresh token and original token.
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        #check if the user already has a password?
        user_id = body['username']
        password = body['password']
        user = User.objects.get(username=user_id)
        if(user != None):
            same_password = check_password(encoded=user.password, password=password)
        else:
            same_password = False

        if same_password == True:
            refresh_token, id =create_refresh_token(user.username)
            token = create_token(user.username)
            print(f'our created and sent token was: {token}')
            
            return JsonResponse({'token': f'{token}' , 'refresh_token': f'{refresh_token}', 'ref_id' : id})
        else:
            return JsonResponse({'error': 'creditials incorrect'}, status=403)


def logout(request):
    #i.e. get refresh token and original token.
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        #check if the user already has a password?
        username = body['username']
        
        user = User.objects.get(username=username)
        Refresh_Token.objects.filter(user=user).delete()

        print('removing refresh tokens of logging out user')

        return JsonResponse({'logged Out': 'logged out'})


        

def check_refresh_token(request):#returns a new short lived token.
    if request.method == 'POST':
        # bearer = request.headers["Authorization"]
        # bearer = bearer[7:]
        # print( f'our recieved token was {bearer}')

        print('starting check request')

        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        id = body['id']
        print(f'refresh token id: {id}')
        token = body["refresh_token"]
        print(f'Our refresh token is: {token}')


        valid = validate_refresh_token(token, id)
        print(f'valid: {valid}')
        

        #if the token is validated - we need to return a new token
        token = create_token(id)

        if valid == True:
            return JsonResponse({'token': f'{token}' })
        elif valid == False:
            return JsonResponse({'error ': 'token invalid'}, status=403)
        else:
            return JsonResponse({'error ': 'expired key'}, status=403)




