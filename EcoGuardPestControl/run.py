# run.py
from app import create_app

app = create_app()

if __name__ == '__main__':
    print("EcoGuard Pest Control System 启动中...")
    app.run(debug=False, port=9231)