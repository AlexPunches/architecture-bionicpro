

Запустить бекенд на локалхосте (на докере не получилось настроить корректную связь с keycloak)
```shell
cd api
python3.11 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
python main.py
```

Свагер http://localhost:8008/docs