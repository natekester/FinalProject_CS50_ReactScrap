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
from .models import User, RefreshToken, ProductId, FailureCause, Scrap, CacheToken, ClosedScrapComments


#########################
#Functions and var to be used by api's 
#TODO clean these functions up and make it a seperate file - more explicit
#TODO setup way more try/excepts to respond with an appropriate code - currently sending too many 500 - when in reality it's bad credentials. 

pag_num = 10; #amount of pages for paginator
encoding_key = 'let us chang it to a random key maybe like 30 characters long? Would change for production versionssss'

def create_refresh_token( user_name):
    #save it associated with a user 


    user = User.objects.filter(username=user_name)
    if(len(user) == 0):
        return JsonResponse({'error': 'cannot get refresh token'}, status=409) #return conflict
        
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

    refr = RefreshToken(token=hashed_token, user=user[0])
    refr.save()
    id = refr.id

    return encoded_token, id


def validate_refresh_token(encoded_token, primary_key):
    #check that the refresh token is valid or not
    
    try:
        #decoding in order to check signature and exp date
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

    ref = RefreshToken.objects.get(pk=primary_key)
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
    #creates a short lived token that is alive for 30 or so seconds
    payload = {
            "name": str(user_name),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
        }
    encoded_token = jwt.encode(payload,  encoding_key, algorithm='HS256') 

    return encoded_token

def validate_token(encoded_token):
    #check that the short lived token is valid
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

        data[f'{position}'] = [item.prod_id.prod_id, item.prod_id.description, item.failure.failure_mode, item.is_open, item.lot_id, item.user.username, item.total_cost, item.time.strftime("%m/%d/%Y, %H:%M:%S"), item.units_scrapped, item.id, position-1]
        position = position + 1

    print(data['1'][0])
    data[0][2] = data['1'][0]
    
    return data

def get_graph_data():
    #returns graph data of all scrap in the system.
    #TODO make this dynamic. It's hard coded and a mess.
    #there is likely a way more efficient method than this.
    #could also make more client side.
    data = {}
    failure = FailureCause.objects.all()
    prod = ProductId.objects.all()
    prod_pos = 0
    products = []

    labels = []
        




    for product in prod:
        #should be only 3 or so.

        # we can move through the primary keys of failures,and then fill in the data positions
        data[prod_pos] = [0,0,0,0,0,0,0,0]
        products.append(product.description)

        

        for x in range(0,9):
            failure = FailureCause.objects.get(pk=(x+1))

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


def get_open_graph_data():
    #returns graph data filtered by open scrap data.
    #TODO make this dynamic. It's hard coded and a mess.
    #there is likely a way more efficient method than this.
    #could also make more client side if we wanted to take backend load off.
    data = {}
    failure = FailureCause.objects.all()
    prod = ProductId.objects.all()
    prod_pos = 0
    products = []

    labels = []
        




    for product in prod:
        #should be only 3 or so.

        # we can move through the primary keys of failures,and then fill in the data positions
        data[prod_pos] = [0,0,0,0,0,0,0,0]
        products.append(product.description)

        

        for x in range(0,9):
            failure = FailureCause.objects.get(pk=(x+1))

            #so lets get each failure mode - query scrap associated with it, make that a bar with the title of that section as the failmode.
            scrap = Scrap.objects.filter(failure=failure, prod_id = product, is_open=True)
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


def get_closed_graph_data():
    #returns graph data filtered by closed data.
    #TODO make this dynamic.  It's hard coded and a mess.
    #there is likely a way more efficient method than this.
    #could also make more client side.
    data = {}
    failure = FailureCause.objects.all()
    prod = ProductId.objects.all()
    prod_pos = 0
    products = []

    labels = []
        




    for product in prod:
        #should be only 3 or so.

        # we can move through the primary keys of failures,and then fill in the data positions
        data[prod_pos] = [0,0,0,0,0,0,0,0]
        products.append(product.description)

        

        for x in range(0,9):
            failure = FailureCause.objects.get(pk=(x+1))

            #so lets get each failure mode - query scrap associated with it, make that a bar with the title of that section as the failmode.
            scrap = Scrap.objects.filter(failure=failure, prod_id = product, is_open=False)
            scrap_cost = 0
            for item in scrap:
                print(f'our scrap isopen should only be false: {item.is_open}')

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
        #token has initial message and ' at end that needs to be removed
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
        #token has initial message and ' at end that needs to be removed       
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
        #token has initial message and ' at end that needs to be removed
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
            prod_id = ProductId.objects.get(pk=prod_id)

            failure = FailureCause.objects.filter(product=prod_id, failure_mode=failure)[0]

            new_scrap = Scrap(prod_id=prod_id,lot_id=lot_id, user=user,total_cost=cost,units_scrapped=units,failure=failure)
            new_scrap.save()
            #lets change our current cache token to be higher.
            current_cache = CacheToken.objects.order_by('id')[0]
            rend = current_cache.current_rendition
            rend = int(rend)
            rend = rend + 1
            new_c_token = CacheToken(current_rendition=rend)
            new_c_token.save()

            return JsonResponse({'scrap': 'scrap created'})
        else:
            return JsonResponse({},status=403 )

            


def graph_data(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        #token has initial message and ' at end that needs to be removed
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')
        page= request.GET.get('page', None)


        valid = validate_token(bearer)
        print('about to send data for all scraps')

        if valid:
            data = get_graph_data()
        
            return JsonResponse(data, safe = False)
        else:
            return JsonResponse({},status=403 )


def open_graph_data(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        #token has initial message and ' at end that needs to be removed
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')
        
        page= request.GET.get('page', None)


        valid = validate_token(bearer)

        if valid:
            data = get_open_graph_data()
        
            return JsonResponse(data, safe = False)
        else:
            return JsonResponse({},status=403 )


def closed_graph_data(request):
    if request.method == "GET":
        bearer = request.headers["Authorization"]
        #token has initial message and ' at end that needs to be removed
        bearer = bearer[9:]
        bearer = bearer[ :-1]
        print( f'our recieved token was {bearer}')
        page= request.GET.get('page', None)


        valid = validate_token(bearer)

        if valid:
            data = get_closed_graph_data()
        
            return JsonResponse(data, safe = False)
        else:
            return JsonResponse({},status=403 )
    
#TODO remove this in production or risk users being ceated through this - leave to Django admin - restricted access to super users
def create_user(request):
    if request.method == 'POST':

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
    #return a short lived token if refresh token is correct
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


        #using the ref token ID sent in message - validate to database token
        db_ref_token = RefreshToken.objects.get(id=ref_id)
        user = db_ref_token.user
        


        if(user != None and db_ref_token != None):
            #check that the username and ref token match up to the hashed refresh token and user in the system
            same_password = check_password(encoded=db_ref_token.token, password=ref_token)
        else:
            same_password = False

        if same_password == True:
            #the username and refresh token match the system - return a new short lived token
            token = create_token(user.username)
            print(f'our created and sent token was: {token}')
            return JsonResponse({'token': f'{token}'})
        else:
            #the user and refresh token were not correct or expired. Return error status
            return JsonResponse({'error': 'creditials incorrect'}, status=403)
        
def check_token(request):
    #validate the short lived token the client has
    if request.method == 'POST':
        bearer = request.headers["Authorization"]
        #bearer has excess char
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
            #TODO figure out a better status for expired key
            return JsonResponse({'error': 'expired key'}, status=403)


def login(request):
    #create and get refresh token and short lived token after providing credentials
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
    #remove refresh token stored associated with the user
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        #check if the user already has a password?
        username = body['username']
        
        user = User.objects.get(username=username)
        RefreshToken.objects.filter(user=user).delete()

        print('removing refresh tokens of logging out user')

        return JsonResponse({'logged Out': 'logged out'})


        

def check_refresh_token(request):
    #returns true if valid and error if invalid
    #returns a new short lived token.
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
        
        if valid == True:
            return JsonResponse({'token': 'true' })
        elif valid == False:
            return JsonResponse({'error ': 'token invalid'}, status=403)
        else:
            return JsonResponse({'error ': 'expired key'}, status=403)


def get_failures(request):
    #retun failure modes associated with a product
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
            prod = ProductId.objects.get(pk=id)
            failures = FailureCause.objects.filter(product=prod)            
            count = 0
            data[f'{count}'] =['']#so the selector has an empty spot to start
            count = 1
            for item in failures:
                data[f'{count}'] = [item.failure_mode]
                count = count + 1

            return JsonResponse(data)
        else:
            return JsonResponse({}, status=403)


def get_products(request):
    #get all products in system and their attributes
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
            prod = ProductId.objects.all()
            count = 0
            data[f'{count}'] =['', '', '','', '' ]#so the selector has an empty spot to start
            count = 1
            for item in prod:
                data[f'{count}'] = [item.prod_id, item.description, item.unit_cost, item.unit, item.id]
                count = count + 1

            return JsonResponse(data)
        else:
            return JsonResponse({}, status=403)



def close_scrap(request):
    #change status of scrap from open to closed
    #TODO update db to handle closing comments
    if request.method == "POST":
        bearer = request.headers["Authorization"]
        print( f'our recieved token was {bearer}')
        bearer = bearer[9:]
        bearer = bearer[ :-1]

        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        print( f'our reduc token was {bearer}')

        valid = validate_token(bearer)
        print(f'valid: {valid}')
        if valid:
            scrap_pk = body['scrapID']
        
        
            scrap = Scrap.objects.get(id=scrap_pk)
            scrap.is_open = False
            scrap.save()

            comment = body['comment']
            com = ClosedScrapComments(scrap=scrap, comment=comment)

            return JsonResponse({'scrap': 'scrap closed'})
        else:
            return JsonResponse({}, status=403)



