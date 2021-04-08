# SECURITY WARNING: keep the secret key used in production secret!
KEY = 'q_=#)8(jb3o&_+%ol)$p(fkz(#6i&+pd)-!166k05zo28m0iyt'

# security variables
SOCIALACCOUNTS = {
    'kakao': {
        'app': {
            # REST API
            'client_id': '568c2628fe5c198647460fc4e4243944',
            # APP ID
            'secret': 556704,
            'key': ''
        }
    }
}

DB = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', #check!
        'HOST': 'database-smartstore.cnuvjza6zuce.ap-northeast-2.rds.amazonaws.com',
        'NAME': 'smartstore', #check!
        'USER': 'admin', #check!
        'OPTIONS': {'init_command': 'SET sql_mode="STRICT_TRANS_TABLES"'},
        'PASSWORD': 'YangJune12!', #check!
        'PORT': '3306' #check!
    }
}