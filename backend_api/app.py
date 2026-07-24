import os
from flask import Flask
from database.db_connection import init_db
from routes.cases import cases_bp
from routes.export_pdf import export_pdf_bp


def create_app():
    app = Flask(__name__)
    app.config['DATABASE'] = os.path.join(app.root_path, 'database', 'cases.db')
    init_db(app.config['DATABASE'])
    app.register_blueprint(cases_bp)
    app.register_blueprint(export_pdf_bp)

    @app.route('/')
    def health_check():
        return {
            'service': 'backend_api',
            'status': 'running',
            'routes': ['/cases', '/export-pdf']
        }

    return app


if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=5000)
