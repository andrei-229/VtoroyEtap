from flask import Flask, request, jsonify
from dotenv import load_dotenv
from dateutil import tz

import os
import psycopg2
import validators
import re
import bcrypt
import uuid
import jwt
import secrets
import datetime

app = Flask(__name__)
load_dotenv()
ADDRES = os.getenv('SERVER_ADDRESS')
HOST = ADDRES.split(':')[0]
PORT = ADDRES.split(':')[1]

post_name = os.getenv('POSTGRES_DATABASE')
post_password = os.getenv('POSTGRES_PASSWORD')
post_user = os.getenv('POSTGRES_USERNAME')
post_host = os.getenv('POSTGRES_HOST')
post_port = os.getenv('POSTGRES_PORT')
print(ADDRES, post_host, post_name, post_user, post_port, post_password)

# try:
connection_postgres = psycopg2.connect(
    dbname=post_name,
    user=post_user,
    password=post_password,
    host=post_host,
    port=post_port
)

# Создание таблицы пользователей
try:
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""CREATE TABLE public.users
            (
            id bigint NOT NULL,
            email text NOT NULL,
            login text NOT NULL,
            password text NOT NULL,
            ispublic text NOT NULL,
            phone text,
            countrycode text NOT NULL,
            image text
            );"""
                )
        connection_postgres.commit()
except psycopg2.errors.DuplicateTable:
    pass

# Создание таблицы токенов
try:
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""CREATE TABLE public.tokens
                (
                    user_id bigint NOT NULL,
                    token text NOT NULL,
                    date_kill text NOT NULL
                );"""
        )
        connection_postgres.commit()
except psycopg2.errors.DuplicateTable:
    pass
except psycopg2.errors.InFailedSqlTransaction:
    connection_postgres.rollback()

# Создание таблицы друзей
try:
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE public.friends
                (
                    user_id bigint NOT NULL,
                    friends_user text
                );"""
        )
        connection_postgres.commit()
        
except psycopg2.errors.DuplicateTable:
    pass
except psycopg2.errors.InFailedSqlTransaction:
    connection_postgres.rollback()

# Создание таблицы постов
try:
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE public.posts_users
                    (
                        id text NOT NULL,
                        user_id bigint NOT NULL,
                        content text NOT NULL,
                        tags text NOT NULL,
                        date text NOT NULL,
                        likesCount text,
                        dislikesCount text
                    );"""
        )
        connection_postgres.commit()
except psycopg2.errors.DuplicateTable:
    pass
except psycopg2.errors.InFailedSqlTransaction:
    connection_postgres.rollback()


@app.route('/api/countries', methods=['GET'])
async def countries():
    filter_reg = request.args.get('region')
    if (filter_reg is not None) and (filter_reg not in ['Europe', 'Africa', 'Americas', 'Oceania', 'Asia']):
        return jsonify({'status': 'error', 'reason': 'Region not found'}), 400
    with connection_postgres.cursor() as cursor:
        if not(filter_reg):
            try: 
                cursor.execute(
                    """SELECT * FROM countries"""
                )
            except psycopg2.errors.InFailedSqlTransaction:
                connection_postgres.rollback()
                cursor.execute(
                    """SELECT * FROM countries"""
                )
        else:
            cursor.execute(
                f"""SELECT * FROM countries
                WHERE region = '{filter_reg}'"""
            )
        con = [{"name": i[1],
                "alpha2": i[2],
                "alpha3": i[3],
                "region": i[4]} for i in cursor.fetchall()]
        con = sorted(con, key=lambda x: x['alpha2'])
        return jsonify(con), 200
    
    
@app.route('/api/countries/<alpha>', methods=['GET'])
async def countries_alpha(alpha):
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM countries WHERE alpha2 = '{alpha}'"""
        )
        
        con = cursor.fetchone()
        if not(con):
            return jsonify({'status': 'error', 'reason': 'The country with the specified code was not found.'}), 404
        return jsonify({"name": con[1],
                        "alpha2": con[2],
                        "alpha3": con[3],
                        "region": con[4]}), 200
    

# Функция проверки валидности пароля
async def is_valid_password(password):
    # Проверка длины пароля
    if len(password) < 6:
        return jsonify({'status': 'error', 'reason': 'Password is too short'}), 400

    # Проверка наличия хотя бы одной буквы верхнего и нижнего регистра
    if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
        return jsonify({'status': 'error', 'reason': 'The password does not contain Latin letters'}), 400

    # Проверка наличия хотя бы одной цифры
    if not re.search("[0-9]", password):
        return jsonify({'status': 'error', 'reason': 'The password does not contain numbers'}), 400

    return 'ok'


# Проверка валидности данных
async def validate_data(obj):
    if 'email' in obj:
        if not (validators.email(obj['email'])) or not(1 < len(obj['email']) < 50):
            return jsonify({'status': 'error', 'reason': 'Invalid mail format'}), 400

    if 'password' in obj:
        pas = await is_valid_password(obj['password'])
        if pas != 'ok':
            return pas
        
    if 'login' in obj:
        if not (1 < len(obj['login']) < 30) or re.search(";/:", obj['login']):
            return jsonify({'status': 'error', 'reason': 'Invalid login format'}), 400
        
    if 'isPublic' in obj:
        if str(obj['isPublic']).title() not in ['True', 'False', 'true', 'false']:
            return jsonify({'status': 'error', 'reason': 'Invalid profile visibility type'}), 400
        
    if 'image' in obj:
        if not(1 < len(obj['image']) < 200):
            return jsonify({'status': 'error', 'reason': 'Invalid link to avatar'}), 400
    with connection_postgres.cursor() as cursor:
        try:
            cursor.execute(
                f"""SELECT * FROM users WHERE email = '{obj['email']}'"""
            )
            if cursor.fetchone():
                return jsonify({'status': 'error', 'reason': 'This user already exists'}), 409
        except KeyError:
            pass
        try:
            cursor.execute(
                f"""SELECT * FROM users WHERE login = '{obj['login']}'"""
            )
            if cursor.fetchone():
                return jsonify({'status': 'error', 'reason': 'This user already exists'}), 409
        except KeyError:
            pass

        if 'phone' in obj:
            cursor.execute(
                f"""SELECT * FROM users WHERE phone = '{obj['phone']}'"""
            )
            if cursor.fetchone():
                return jsonify({'status': 'error', 'reason': 'This number is already in use'}), 409

        if 'countryCode' in obj:
            cursor.execute(
                f"""SELECT * FROM countries WHERE alpha2 = '{obj['countryCode']}'"""
            )
            if not (cursor.fetchone()):
                return jsonify({'status': 'error', 'reason': 'There is no such country'}), 400
        
    return 'ok'

# Функция регистрации пользователя
async def register(obj):
    try:
        new_user = {'login': obj['login'],
                    'email': obj['email'],
                    'countryCode': obj['countryCode'],
                    'isPublic': obj['isPublic']}
    except KeyError:
        return jsonify({'status': 'error', 'reason': 'Enter all details'}), 400
    
    status = await validate_data(obj)
    if status != 'ok':
        return status
    
    with connection_postgres.cursor() as cursor:
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(obj['password'].encode('utf-8'), salt).decode('utf-8')
        id_u = int(str(uuid.uuid4().int)[:-20])
        image = obj['image'] if 'image' in obj else ''
        phone = obj['phone'] if 'phone' in obj else ''
        try:
            if 'image' in obj:
                new_user['image'] = obj['image']
            if 'phone' in obj:
                new_user['phone'] = obj['phone']
            cursor.execute(
                    f"""INSERT INTO users (id, email, login, password, ispublic, phone, countrycode, image) VALUES
                        ({id_u},'{obj['email']}','{obj['login']}','{password}','{obj['isPublic']}','{phone}','{obj['countryCode']}', '{image}')"""
                )
            connection_postgres.commit()
            return jsonify({'profile': new_user}), 201
        except psycopg2.errors.InFailedSqlTransaction:
            cursor.execute("""ROLLBACK""")
            connection_postgres.commit()
            return jsonify({'status': 'error', 'reason': 'Transaction error'}), 400
    
        
@app.route('/api/auth/register', methods=['POST'])
async def auth_register():
    try:
        obj = request.get_json()
    except Exception:
        return jsonify({'status': 'error', 'reason': 'Invalid data'}), 401
    
    return  await register(obj)


# Создание токена пользователя
async def create_token(obj):
    secret_key = secrets.token_urlsafe(20)

    token = jwt.encode(obj, secret_key, algorithm='HS256')
    return token


async def check_token(token):
    with connection_postgres.cursor() as cursor:
        try:
            cursor.execute(
                f"""SELECT * FROM tokens WHERE token = '{token}'"""
            )
        except psycopg2.errors.InFailedSqlTransaction:
            connection_postgres.rollback()
            cursor.execute(
                f"""SELECT * FROM tokens WHERE token = '{token}'"""
            )
        session = cursor.fetchone()
        if not(session):
            return jsonify({'status': 'error', 'reason': 'Token not found'}), 401
        date = session[2]
        d = [int(i) for i in date.split('-')]
        date_kill = datetime.datetime(day=d[0], month=d[1], year=d[2], hour=d[-1])
        t = datetime.datetime.now()
        if not(date_kill > t):
            return jsonify({'status': 'error', 'reason': 'Token expired'}), 401
        return True


async def login(obj):
    # try:
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT password FROM users WHERE login = '{obj['login']}'"""
        )
        password = cursor.fetchone()
        if not(password):
            return jsonify({'status': 'error', 'reason': 'User is not found'}), 401
        password = password[0]
        if bcrypt.checkpw(obj['password'].encode('utf-8'), password.encode('utf-8')):
            
            # Создание токена
            token = await create_token(obj)
            obj['token'] = token
            
            # Получение пользователя
            cursor.execute(
                f"""SELECT id FROM users WHERE login = '{obj['login']}'"""
            )
            user_id = cursor.fetchone()[0]
            
            # Дата окончания работы токена
            date_next = datetime.datetime.now() + datetime.timedelta(days=1)
            date = f'{date_next.day}-{date_next.month}-{date_next.year}-{date_next.hour}'
            
            cursor.execute(
                f"""SELECT * FROM tokens WHERE user_id = {user_id}"""
            )
            
            # Если пользователь еще не логинился, то создаем для него место в бд
            if not(cursor.fetchone()):
                cursor.execute(
                    f"""INSERT INTO tokens (user_id, token, date_kill) VALUES
                        ({user_id},'{token}','{date}')"""
                )
                connection_postgres.commit()
                return jsonify(obj), 200
            cursor.execute(
                f"""UPDATE tokens
                    SET token = '{token}', date_kill = '{date}'
                    WHERE user_id = {user_id}"""
            )
            connection_postgres.commit()
            return jsonify(obj), 200
        return jsonify({'status': 'error', 'reason': 'Wrong password'}), 401


@app.route('/api/auth/sign-in', methods=['POST'])
async def auth_login():
    try:
        obj = request.get_json()
    except Exception:
        return jsonify({'status': 'error', 'reason': 'login or password not received'}), 401
    if (obj is None) or ('login' not in obj) or ('password' not in obj):
        return jsonify({'status': 'error', 'reason': 'login or password not received'}), 401
    return await login(obj)


@app.route('/api/me/profile', methods=['GET', 'PATCH'])
async def me_profile():
    obj = []
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    worked_token = await check_token(token)
    if worked_token is not True:
        return worked_token
    
    with connection_postgres.cursor() as cursor:
        if request.method == 'GET':
            cursor.execute(
                f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
            )
            user = cursor.fetchone()
            return_json = {'login': user[2],
                           'email': user[1],
                           'countryCode': user[6],
                           'isPublic': user[4]}
            if len(user[7]) > 0:
                return_json['image'] = user[7]
            if len(user[5]) > 0:
                return_json['phone'] = user[5]
            return jsonify(return_json), 200
        if request.method == 'PATCH':
            try:
                obj = request.get_json()
            except Exception:
                return jsonify({'status': 'error', 'reason': 'invalid data'})
            arr_key = [i for i in obj if i in [
                'countryCode', 'isPublic', 'phone', 'image']]
            if len(arr_key) < 1:
                return jsonify({'status': 'error', 'reason': 'invalid data'})
            cursor.execute(
                    f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
                )
            user = cursor.fetchone()[0]
            info = await validate_data(obj)
            if info != 'ok':
                return info
            str_key = '('+', '.join(arr_key)+')' if len(arr_key) > 1 else arr_key[0]
            str_value = '('+', '.join([f"'{obj[i]}'" for i in arr_key])+')' if len(arr_key) > 1 else f"'{obj[arr_key[0]]}'"
            cursor.execute(
                f"""UPDATE users
                        SET {str_key} = {str_value}
                        WHERE id = {user}"""
            )
            connection_postgres.commit()
            cursor.execute(
                f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
            )
            user = cursor.fetchone()
            return jsonify({'login': user[2],
                            'email': user[1],
                            'countryCode': user[6],
                            'isPublic': user[4],
                            'phone': user[5],
                            'image': user[7]}), 200
            
            
async def check_friends(my_login, user_login):
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT friends_user FROM friends WHERE user_id = (SELECT user_id FROM users WHERE login = '{user_login}')"""
        )
        user_friends = cursor.fetchone()
        if not(user_friends):
            return False
        user_friends = user_friends[0].split(';')
        for i in user_friends:
            if my_login in i:
                return True
        return False
            
@app.route('/api/profiles/<login>', methods=['GET'])
async def profile_users(login):
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)
    if status_token is not True:
        return status_token
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM users
               WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        mabe_is_me = cursor.fetchone()
        my_login = mabe_is_me[2]
        if my_login == login:
            return jsonify({
                'login': my_login,
                'email': mabe_is_me[1],
                'countryCode': mabe_is_me[-1],
                'isPublic': mabe_is_me[4],
                'phone': mabe_is_me[5]
            }), 200
        
        cursor.execute(
            f"""SELECT * FROM users WHERE login = '{login}'"""
        )
        user = cursor.fetchone()
        if not(user):
            return jsonify({'status': 'error', 'reason': 'User is not found'}), 403
        if user[4] != "True":
            if await check_friends(my_login, user[2]):
                    return jsonify({'profile': {
                        'login': user[2],
                        'email': user[1],
                        'countryCode': user[-1],
                        'isPublic': user[4],
                        'phone': user[5]
                    }}), 200
            
            return jsonify({'status': 'error', 'reason': 'Profile is hidden'}), 403
        return jsonify({'profile': {
            'login': user[2],
            'email': user[1],
            'countryCode': user[-1],
            'isPublic': user[4],
            'phone': user[5]
        }}), 200
        
        
@app.route('/api/me/updatePassword', methods=['POST'])
async def updatePassword():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    
    status_token = await check_token(token)
    if status_token is not True:
        return status_token
    
    try:
        obj = request.get_json()
    except Exception:
        return jsonify({'status': 'error', 'reason': 'invalid data'}), 401
    if (obj is None) or ('oldPassword' not in obj) or ('newPassword' not in obj):
        return jsonify({'status': 'error', 'reason': 'old or new password not received'}), 401
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT password FROM users
               WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )

        password = cursor.fetchone()[0]
        if bcrypt.checkpw(obj['oldPassword'].encode('utf-8'), password.encode('utf-8')):
            pas = await is_valid_password(obj['newPassword'])
            if pas != 'ok':
                return pas
            
            salt = bcrypt.gensalt()
            password = bcrypt.hashpw(obj['newPassword'].encode('utf-8'), salt).decode('utf-8')
            
            # Обновление пароля
            cursor.execute(
                f"""UPDATE users
                SET password = '{password}'
                WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
            )
            
            with connection_postgres.cursor() as cursor2:
                # Прекращение работы токена
                cursor2.execute(
                    f"""DELETE FROM tokens
                    WHERE token = '{token}'"""
                )
            connection_postgres.commit()
            
            return jsonify({"status": "ok"}), 200
        
        return jsonify({'status': 'error', 'reason': 'Wrong password'}), 403
    
    
@app.route('/api/friends/add', methods=['POST'])
async def add_friend():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token) # Проверка токена на валидноть
    if status_token is not True:
        return status_token
    
    try:
        obj = request.get_json()
    except Exception:
        return jsonify({'status': 'error', 'reason': 'invalid data'}), 401
    if obj is None or ('login' not in obj):
        return jsonify({'status': 'error', 'reason': 'login not received'}), 401
    
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT login FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        login_user = cursor.fetchone()[0]
        if obj['login'] == login_user: # Если пользователь добавляет сам себя, то сразу возвращаем статус 'ok'
            return jsonify({'status': 'ok'}), 200
        
        cursor.execute(
            f"""SELECT * FROM users WHERE login = '{obj['login']}'"""
        )
        user_fiend = cursor.fetchone() # Поиск пользователя по переданному токену
        if not (user_fiend):
            return jsonify({'status': 'error', 'reason': 'User is not found'}), 404
        
        cursor.execute(
            f"""SELECT user_id FROM tokens WHERE token = '{token}'"""
        )
        user_id = cursor.fetchone()[0] # Получение айди пользователя по токену
        
        cursor.execute(
            f"""SELECT * FROM friends WHERE user_id = {user_id}"""
        )
        list_friends = cursor.fetchone() # Проверка есть ли строка с таким user_id
        date_next = datetime.datetime.now()
        date_next = date_next.replace(microsecond=0)
        date = date_next.astimezone(tz.tzutc()).isoformat()
        date = date.replace('+', 'Z')
        if not(list_friends):
            # Если такой строки нет, то создаем
            cursor.execute(
                f"""INSERT INTO friends (user_id, friends_user) VALUES
                    ({user_id}, '{obj['login']}/{date}')"""
            )
            
            connection_postgres.commit()
            return jsonify({'status': 'ok'}), 200
        
        friends = list_friends[1].split(';')
        for i in friends:
            if obj['login'] in i:
                return jsonify({'status': 'ok'}), 200
        
        friends.append(f'{obj["login"]}/{date}')
        friends = ';'.join(friends)
        cursor.execute(
            f"""UPDATE friends SET friends_user = '{friends}' WHERE user_id = {user_id}"""
        )
        
        connection_postgres.commit()
        return jsonify({'status': 'ok'}), 200
    
    
@app.route('/api/friends/remove', methods=['POST'])
async def remove_friends():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token

    try:
        obj = request.get_json()
    except Exception:
        return jsonify({'status': 'error', 'reason': 'invalid data'}), 401
    if obj is None or ('login' not in obj):
        return jsonify({'status': 'error', 'reason': 'login not received'}), 401
    
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM friends WHERE user_id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        friends = cursor.fetchone()
        if not(friends):
            return jsonify({'status': 'ok', 'reason': 'you have no friends('}), 200
        
        friends = friends[1].split(';')
        friend = ''
        for i in friends:
            if obj['login'] in i:
                friend = i
        friends.remove(friend)
        friends = ';'.join(friends)
        cursor.execute(
            f"""UPDATE friends
               SET friends_user = '{friends}' WHERE user_id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        connection_postgres.commit()
        
        return jsonify({'status': 'ok'}), 200
    
    
@app.route('/api/friends', methods=['GET'])
async def friends():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token

    limit = request.args.get('limit')
    offset = request.args.get('offset')
    if not(limit):
        limit = 5
    try:
        limit = int(limit)
    except:
        limit = None
        
    try:
        offset = int(offset)
    except:
        offset = None
    
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT friends_user FROM friends WHERE user_id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        friends = cursor.fetchone()
        if not(friends):
            return jsonify([]), 200
        
        friends = friends[0].split(';')[::-1]
        if offset:
            friends = friends[offset:]
        
        if limit:
            friends = [friends[i] for i in range(limit)]
        arr = [{'login': i.split('/')[0], 'addedAt': i.split('/')[1]} for i in friends]
        
        return jsonify(arr), 200
    
    
@app.route('/api/posts/new', methods=['POST'])
async def new_post():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token
    
    try:
        obj = request.get_json()
    except Exception:
        return jsonify({'status': 'error', 'reason': 'invalid data'}), 401
    if (obj is None) or ('content' not in obj) or ('tags' not in obj):
        return jsonify({'status': 'error', 'reason': 'content or tags not received'})
    if type(obj['tags']) != list:
        return jsonify({'status': 'error', 'reason': 'type tags is not list'}), 401
    if len(obj['content']) > 1000:
        return jsonify({'status': 'error', 'reason': 'Content too long'}), 401
    
    publication_id = uuid.uuid4()
    
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        user = cursor.fetchone()
        date_next = datetime.datetime.now()
        date_next = date_next.replace(microsecond=0)
        date = date_next.astimezone(tz.tzutc()).isoformat()
        date = date.replace('+', 'Z')
        tags = ';'.join(obj['tags'])
        
        cursor.execute(
            f"""INSERT INTO posts_users (id, user_id, content, tags, date, likescount, dislikescount) VALUES
                    ('{publication_id}', {user[0]}, '{obj['content']}', '{tags}', '{date}', '', '')"""
        )
        
        connection_postgres.commit()
        return jsonify({'id': publication_id,
                        'content': obj['content'],
                        'author': user[2],
                        'tags': obj['tags'],
                        'createdAt': date,
                        'likesCount': 0,
                        'dislikesCount': 0}), 200
        
        
@app.route('/api/posts/<postId>', methods=['GET'])
async def post_id(postId):
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token
    
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        my_profile = cursor.fetchone()
        
        cursor.execute(
            f"""SELECT * FROM posts_users WHERE id = '{postId}'"""
        )
        
        post = cursor.fetchone()
        if not(post):
            return jsonify({'status': 'error', 'reason': 'Post not found'}), 404
        likes = len(post[5].split(';')) if post[5].split(';')[0] != '' else 0
        dislikes = len(post[6].split(';')) if post[6].split(';')[0] != '' else 0
        
        cursor.execute(
            f"""SELECT * FROM users WHERE id = {post[1]}"""
        )
        
        author = cursor.fetchone()
        return_post = {'id': post[0],
                       'content': post[2],
                       'author': author[2],
                       'tags': post[3].split(';'),
                       'createdAt': post[4],
                       'likesCount': likes,
                       'dislikesCount': dislikes}
        if author[2] == my_profile[2]:
            return jsonify(return_post), 200
        if author[4] != "True":
            if await check_friends(my_profile[2], author[2]):
                return jsonify(return_post), 200
            
            return jsonify({'status': 'error', 'reason': 'Доступ закрыт'}), 404
            
        return jsonify(return_post), 200
    
    
@app.route('/api/posts/feed/my', methods=['GET'])
async def my_posts():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token

    limit = request.args.get('limit')
    offset = request.args.get('offset')
    if not(limit):
        limit = 5
    try:
        limit = int(limit)
    except:
        limit = None

    try:
        offset = int(offset)
    except:
        offset = None
        
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM posts_users WHERE user_id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        posts = cursor.fetchall()
        
        cursor.execute(
            f"""SELECT login FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )

        author = cursor.fetchone()[0]
        
        if not(posts):
            return jsonify([]), 200

        posts = posts[::-1]
        if offset:
            posts = posts[offset:]
        
        if limit:
            posts = [posts[i]
                     for i in range(limit)] if len(posts) > limit else posts
    
    return jsonify([{'id': post[0],
                     'content': post[2],
                     'author': author,
                     'tags': post[3],
                     'createdAt': post[4],
                     'likesCount': len(post[5].split(';')) if post[5].split(';')[0] != '' else 0,
                     'dislikesCount': len(post[6].split(';')) if post[6].split(';')[0] != '' else 0} for post in posts]), 200
    
    
@app.route('/api/posts/feed/<login>', methods=['GET'])
async def login_posts(login):
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token

    limit = request.args.get('limit')
    offset = request.args.get('offset')
    if not (limit):
        limit = 5
    try:
        limit = int(limit)
    except:
        limit = None

    try:
        offset = int(offset)
    except:
        offset = None
        
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM users WHERE login = '{login}'"""
        )
        
        user_author = cursor.fetchone()
        
        if not(user_author):
            return jsonify({'status': 'error', 'reason': 'User is not found'}), 404
        
        cursor.execute(
            f"""SELECT * FROM posts_users WHERE user_id = {user_author[0]}"""
        )
        
        posts = cursor.fetchall()
        if not(posts):
            return jsonify([]), 200
        
        posts = posts[::-1]
        
        if offset:
            posts = posts[offset:]
        if limit:
            posts = [posts[i] for i in range(limit)] if len(posts) > limit else posts
        
        posts = [{'id': post[0],
                     'content': post[2],
                     'author': login,
                     'tags': post[3].split(';'),
                     'createdAt': post[4],
                     'likesCount': len(post[5].split(';')) if post[5].split(';')[0] != '' else 0,
                     'dislikesCount': len(post[6].split(';')) if post[6].split(';')[0] != '' else 0} for post in posts]
        
        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )
        
        my_profile = cursor.fetchone()
        
        if my_profile[2] == login:
            
            return jsonify(posts), 200
        
        if user_author[4] != 'True':
            if await check_friends(my_profile[2], login):
                    return jsonify(posts), 200
            return jsonify({'status': 'error', 'reason': 'Access closed'}), 404
        
        return jsonify(posts), 200
    
    
@app.route('/api/posts/<postId>/like', methods=['POST'])
async def post_like(postId):
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token
    
    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )

        my_profile = cursor.fetchone()

        cursor.execute(
            f"""SELECT * FROM posts_users WHERE id = '{postId}'"""
        )

        post = cursor.fetchone()
        if not(post):
            jsonify({'status': 'error', 'reason': 'Post not found'}), 404
        
        likes = post[5].split(';')
        dislikes = post[6].split(';')
        if likes[0] == '':
            likes[0] = my_profile[2]
        else:
            if my_profile[2] not in likes:
                likes.append(my_profile[2])
        if my_profile[2] in dislikes:
            dislikes.remove(my_profile[2])
        if len(dislikes) == 0:
            dislikes.append('')
            
        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM posts_users WHERE id = '{postId}')"""
        )
        
        user_author = cursor.fetchone()
        
        return_post = {'id': post[0],
                       'content': post[2],
                       'author': user_author[2],
                       'tags': post[3].split(';'),
                       'createdAt': post[4],
                       'likesCount': len(likes),
                       'dislikesCount': len(dislikes) if dislikes[0] != '' else 0}
        
        if my_profile[2] == user_author[2]:
            cursor.execute(
                f"""UPDATE posts_users
                    SET (likescount, dislikescount) = ('{';'.join(likes)}', '{';'.join(dislikes)}')
                    WHERE id = '{postId}'"""
            )
            connection_postgres.commit()
            return jsonify(return_post), 200
        
        if user_author[4] != 'True':
            if await check_friends(my_profile[2], user_author[2]):
                cursor.execute(
                    f"""UPDATE posts_users
                        SET (likescount, dislikescount) = ('{';'.join(likes)}', '{';'.join(dislikes)}')
                        WHERE id = '{postId}'"""
                )
                connection_postgres.commit()
                return return_post
            return jsonify({'status': 'error', 'reason': 'Доступ закрыт'}), 404
        
        cursor.execute(
                    f"""UPDATE posts_users
                        SET (likescount, dislikescount) = ('{';'.join(likes)}', '{';'.join(dislikes)}')
                        WHERE id = '{postId}'"""
                )
        connection_postgres.commit()
        return jsonify(return_post), 200
    
    
@app.route('/api/posts/<postId>/dislike', methods=['POST'])
async def post_dislike(postId):
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'status': 'error', 'reason': 'token not received'}), 401
    token = token.split(' ')[1]
    status_token = await check_token(token)  # Проверка токена на валидноть
    if status_token is not True:
        return status_token

    with connection_postgres.cursor() as cursor:
        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM tokens WHERE token = '{token}')"""
        )

        my_profile = cursor.fetchone()

        cursor.execute(
            f"""SELECT * FROM posts_users WHERE id = '{postId}'"""
        )

        post = cursor.fetchone()
        if not (post):
            jsonify({'status': 'error', 'reason': 'Post not found'}), 404

        likes = post[5].split(';')
        dislikes = post[6].split(';')
        if dislikes[0] == '':
            dislikes[0] = my_profile[2]
        else:
            if my_profile[2] not in dislikes:
                dislikes.append(my_profile[2])
        if my_profile[2] in likes:
            likes.remove(my_profile[2])
        if len(likes) == 0:
            likes.append('')

        cursor.execute(
            f"""SELECT * FROM users WHERE id = (SELECT user_id FROM posts_users WHERE id = '{postId}')"""
        )

        user_author = cursor.fetchone()
        return_post = {'id': post[0],
                       'content': post[2],
                       'author': user_author[2],
                       'tags': post[3].split(';'),
                       'createdAt': post[4],
                       'likesCount': len(likes) if likes[0] != '' else 0,
                       'dislikesCount': len(dislikes)}
        
        if my_profile[2] == user_author[2]:
            cursor.execute(
                f"""UPDATE posts_users
                    SET (likescount, dislikescount) = ('{';'.join(likes)}', '{';'.join(dislikes)}')
                    WHERE id = '{postId}'"""
            )
            connection_postgres.commit()
            return jsonify(return_post), 200

        if user_author[4] != 'True':
            if await check_friends(my_profile[2], user_author[2]):
                cursor.execute(
                    f"""UPDATE posts_users
                        SET (likescount, dislikescount) = ('{';'.join(likes)}', '{';'.join(dislikes)}')
                        WHERE id = '{postId}'"""
                )
                connection_postgres.commit()
                return return_post
            return jsonify({'status': 'error', 'reason': 'Access closed'}), 404

        cursor.execute(
            f"""UPDATE posts_users
                        SET (likescount, dislikescount) = ('{';'.join(likes)}', '{';'.join(dislikes)}')
                        WHERE id = '{postId}'"""
        )
        connection_postgres.commit()
        return jsonify(return_post), 200
        

@app.route('/api/ping', methods=['GET'])
async def send():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host=HOST, port=PORT)
