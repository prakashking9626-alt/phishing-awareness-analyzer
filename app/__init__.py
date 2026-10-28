"""
Application factory initializing the Flask application, security headers,
and hardened error handlers.
"""
from flask import Flask, jsonify, request, render_template
from app.config import Config


def create_app(config_class=Config):
    """Factory function to build and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Register blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    # Hardening: Inject security headers into every HTTP response
    @app.after_request
    def set_security_headers(response):
        for header, value in app.config.get("SECURITY_HEADERS", {}).items():
            response.headers[header] = value
        return response

    # Centralized Error Handlers
    def handle_error_response(message: str, status_code: int):
        # Return JSON if requested by client or if accessing /api routes
        if request.path.startswith("/api/") or request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({
                "is_valid": False,
                "error": message,
                "status_code": status_code
            }), status_code
        return render_template("base.html", error_message=message, error_code=status_code), status_code

    @app.errorhandler(400)
    def bad_request(error):
        return handle_error_response("Bad Request: Malformed or invalid input supplied.", 400)

    @app.errorhandler(404)
    def not_found(error):
        return handle_error_response("Resource Not Found: The requested endpoint does not exist.", 404)

    @app.errorhandler(405)
    def method_not_allowed(error):
        return handle_error_response("Method Not Allowed: HTTP method is not permitted for this endpoint.", 405)

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return handle_error_response("Payload Too Large: The request exceeds the maximum permitted size limit (100 KB).", 413)

    @app.errorhandler(500)
    def internal_server_error(error):
        return handle_error_response("Internal Server Error: An unexpected error occurred while analyzing the input.", 500)

    return app
