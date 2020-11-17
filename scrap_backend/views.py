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
#TODO setup way more try/excepts to respond with an appropriate code - currently sending too many 500 - when in reality it's bad credentials. 
#

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
        print('the submitted token is expired')
        return False
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

def validate_token(encoded_token):
    
    try:
        decoded_key = jwt.decode(encoded_token, encoding_key, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:

        print('the submitted token is expired')
        return False
    except:
        print('invalid signature!!')
        return False
    
    return True


def pagination_json( info, curr_page):
            
    pages = Paginator( info, pag_num)
    page = pages.get_page(curr_page)
    
    data = {}
    position = 1
    num_items = len(page)
    
    data[0] = [page.has_next(), page.has_previous(), curr_page, num_items]
    for item in page:

        data[f'{position}'] = [item.prod_id.prod_id, item.prod_id.description, item.failure.failure_mode, item.is_open, item.lot_id, item.user.username, item.total_cost, item.time.strftime("%m/%d/%Y, %H:%M:%S"), item.units_scrapped , position-1]
        position = position + 1

    print(data['1'][0])
    data[0][2] = data['1'][0]
    
    return data

def get_graph_data():
    #TODO make this dynamic. It's so icky.
    #there is likely a way more efficient method than this.
    #could also make more client side.
    data = {}
    failure = Failure_Cause.objects.all()
    prod = Product_Id.objects.all()
    prod_pos = 0
    products = []

    labels = []
        




    for product in prod:
        #should be only 3 or so.

        # we can move through the primary keys of failures,and then fill in the data positions
        data[prod_pos] = [0,0,0,0,0,0,0,0]
        products.append(product.description)

        

        for x in range(0,9):
            failure = Failure_Cause.objects.get(pk=(x+1))

            #so lets get each failure mode - query scrap associated with it, make that a bar with the title of that section as the failmode.
            scrap = Scrap.objects.filter(failure=failure, prod_id = product)
            scrap_cost = 0
            for item in scrap:
                scrap_cost = item.total_cost + scrap_cost

            if x == 4: #overlap of failure modes should create new table, but on a timeline
                data[prod_pos][2] = scrap_cost + data[prod_pos][2]
            elif x == 6:
                data[prod_pos][3] = scrap_cost + data[prod_pos][3]
            elif x==5:
                data[prod_pos][4] = scrap_cost + data[prod_pos][4]
            elif x==7:
                data[prod_pos][5] = scrap_cost + data[prod_pos][5]
            elif x==8:
                data[prod_pos][6] = scrap_cost + data[prod_pos][6]
            else:
                data[prod_pos][x] = scrap_cost

            if prod_pos == 0:
                if x != 4 and x != 6: #overlap of failure modes should create new table, but on a timeline
                    print(f'our x is: {x}')
                    print(f'our failure mode is: {failure.failure_mode}')
                    labels.append(failure.failure_mode)
                    



            

        prod_pos = prod_pos + 1
    
    print(f'our labels are: {labels}')

        

    
    return [ data, products, labels ]








##########################################
#Starting API's
##########################################  







def open_scrap(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')
        page= request.GET.get('page', None)


        valid = validate_token(bearer)

        if valid:
            info = Scrap.objects.filter( is_open=True)

            print(f'valid: {valid}')

            data = pagination_json(info, page)

        
            return JsonResponse(data, safe = False)
        else:
            return JsonResponse({},status=403 )


def closed_scrap(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')
        page= request.GET.get('page', None)


        valid = validate_token(bearer)

        if valid:
            info = Scrap.objects.filter( is_open=False)

            print(f'valid: {valid}')

            data = pagination_json(info, page)

        
            return JsonResponse(data, safe = False)
        else:
            return JsonResponse({},status=403 )



def create_scrap(request):
    if request.method == "POST":
        bearer = request.headers["Authorization"]
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')

        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        username = body['user']
        cost = body['cost']
        units = body['units']
        prod_id = body['prodID']
        failure = body['failure']
        lot_id = body['lotID']


        valid = validate_token(bearer)
        print(f'valid: {valid}')
        if valid:
            user = User.objects.get(username=username)
            prod_id = Product_Id.objects.get(pk=prod_id)

            failure = Failure_Cause.objects.filter(product=prod_id, failure_mode=failure)[0]

            new_scrap = Scrap(prod_id=prod_id,lot_id=lot_id, user=user,total_cost=cost,units_scrapped=units,failure=failure)
            new_scrap.save()
            #lets change our current cache token to be higher.
            current_cache = Cache_Token.objects.order_by('id')[0]
            rend = current_cache.current_rendition
            rend = int(rend)
            rend = rend + 1
            new_c_token = Cache_Token(current_rendition=rend)
            new_c_token.save()

            return JsonResponse({'scrap': 'scrap created'})
        else:
            return JsonResponse({},status=403 )

            


def graph_data(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')
        page= request.GET.get('page', None)


        valid = validate_token(bearer)

        if valid:
            data = get_graph_data()
        
            return JsonResponse(data, safe = False)
        else:
            return JsonResponse({},status=403 )
    

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
        print(f'Our Ref token is: {ref_token}')
        ref_token = ref_token[2:]
        ref_token = ref_token[:-1]
        print(f'Our Ref token after apend: {ref_token}')

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
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')

        valid = validate_token(bearer)
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

        print('starting check request')

        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        id = body['id']
        print(f'refresh token id: {id}')
        token = body["refresh_token"]
        token = token[2:]
        token = token[:-1]
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


def get_failures(request):

    if request.method == "GET":
        bearer = request.headers["Authorization"]
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')

        id = request.GET.get('id', None)
        print(f'our id was: {id}')

        valid = validate_token(bearer)
        print(f'valid: {valid}')
        if valid:
            data = {}
            prod = Product_Id.objects.get(pk=id)
            failures = Failure_Cause.objects.filter(product=prod)            
            count = 0
            data[f'{count}'] =['']#so the selector has an empty spot to start
            count = 1
            for item in failures:
                data[f'{count}'] = [item.failure_mode]
                count = count + 1

            return JsonResponse(data)
        else:
            return JsonResponse({}, status=403)



    
    return JsonResponse()


def get_products(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        print( f'our recieved token was {bearer}')
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our reduc token was {bearer}')



        valid = validate_token(bearer)
        print(f'valid: {valid}')
        if valid:
            data = {}
            prod = Product_Id.objects.all()
            count = 0
            data[f'{count}'] =['', '', '','', '' ]#so the selector has an empty spot to start
            count = 1
            for item in prod:
                data[f'{count}'] = [item.prod_id, item.description, item.unit_cost, item.unit, item.id]
                count = count + 1

            return JsonResponse(data)
        else:
            return JsonResponse({}, status=403)



