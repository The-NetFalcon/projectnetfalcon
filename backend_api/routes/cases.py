import sqlite3
from flask import Blueprint, current_app, jsonify, request
from database.db_connection import get_connection

cases_bp = Blueprint('cases', __name__, url_prefix='/cases')


def get_db_connection():
    database_path = current_app.config['DATABASE']
    connection = get_connection(database_path)
    connection.row_factory = sqlite3.Row
    return connection


@cases_bp.route('', methods=['GET'])
def list_cases():
    with get_db_connection() as connection:
        rows = connection.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()
        return jsonify([dict(row) for row in rows])


@cases_bp.route('/<int:case_id>', methods=['GET'])
def get_case(case_id: int):
    with get_db_connection() as connection:
        row = connection.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
        if row is None:
            return jsonify({'error': 'Case not found'}), 404
        return jsonify(dict(row))


@cases_bp.route('', methods=['POST'])
def create_case():
    request_data = request.get_json(force=True, silent=True) or {}
    title = request_data.get('title')
    description = request_data.get('description', '')
    status = request_data.get('status', 'open')

    if not title or not isinstance(title, str):
        return jsonify({'error': 'Title is required and must be a string'}), 400

    with get_db_connection() as connection:
        cursor = connection.execute(
            'INSERT INTO cases (title, description, status) VALUES (?, ?, ?)',
            (title.strip(), description.strip(), status.strip())
        )
        connection.commit()
        case_id = cursor.lastrowid
        case = connection.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
        return jsonify(dict(case)), 201


@cases_bp.route('/<int:case_id>', methods=['PUT'])
def update_case(case_id: int):
    request_data = request.get_json(force=True, silent=True) or {}
    title = request_data.get('title')
    description = request_data.get('description')
    status = request_data.get('status')

    fields = []
    values = []

    if title is not None:
        fields.append('title = ?')
        values.append(title.strip())
    if description is not None:
        fields.append('description = ?')
        values.append(description.strip())
    if status is not None:
        fields.append('status = ?')
        values.append(status.strip())

    if not fields:
        return jsonify({'error': 'No update fields provided'}), 400

    values.append(case_id)

    with get_db_connection() as connection:
        cursor = connection.execute(
            f'UPDATE cases SET {", ".join(fields)} WHERE id = ?',
            values
        )
        if cursor.rowcount == 0:
            return jsonify({'error': 'Case not found'}), 404
        connection.commit()
        case = connection.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
        return jsonify(dict(case))


@cases_bp.route('/<int:case_id>', methods=['DELETE'])
def delete_case(case_id: int):
    with get_db_connection() as connection:
        cursor = connection.execute('DELETE FROM cases WHERE id = ?', (case_id,))
        if cursor.rowcount == 0:
            return jsonify({'error': 'Case not found'}), 404
        connection.commit()
        return '', 204
