"""
Blueprint routes for the Phishing Awareness Analyzer.
Exposes frontend rendering and hardened JSON API endpoints.
"""
from flask import Blueprint, render_template, request, jsonify
from app.analyzers.url_analyzer import analyze_url
from app.analyzers.email_analyzer import analyze_email
from app.analyzers.scoring_engine import evaluate_artifact
from app.data.sample_payloads import SAMPLES

main_bp = Blueprint("main", __name__)


@main_bp.route("/", methods=["GET"])
def index():
    """Renders the single-page cybersecurity awareness dashboard."""
    return render_template("index.html")


@main_bp.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    """
    Analyzes a submitted URL for phishing indicators using local static heuristics.
    Expects JSON: {"url": "<target_url>"}
    """
    if not request.is_json:
        return jsonify({
            "is_valid": False,
            "error": "Request Content-Type must be application/json"
        }), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({
            "is_valid": False,
            "error": "Invalid or malformed JSON payload."
        }), 400

    url = data.get("url")
    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({
            "is_valid": False,
            "error": "URL field is required and cannot be empty."
        }), 400

    if len(url) > 4096:
        return jsonify({
            "is_valid": False,
            "error": "URL exceeds maximum permitted length (4096 characters)."
        }), 400

    analysis = analyze_url(url.strip())
    result = evaluate_artifact(analysis)
    return jsonify(result), 200


@main_bp.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    """
    Analyzes submitted email body and optional sender for phishing heuristics.
    Expects JSON: {"email_body": "<text>", "sender": "<optional_header>"}
    """
    if not request.is_json:
        return jsonify({
            "is_valid": False,
            "error": "Request Content-Type must be application/json"
        }), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({
            "is_valid": False,
            "error": "Invalid or malformed JSON payload."
        }), 400

    email_body = data.get("email_body")
    if not email_body or not isinstance(email_body, str) or not email_body.strip():
        return jsonify({
            "is_valid": False,
            "error": "Email body is required and cannot be empty."
        }), 400

    if len(email_body) > 65536:
        return jsonify({
            "is_valid": False,
            "error": "Email body exceeds maximum permitted length (64 KB)."
        }), 400

    raw_sender = data.get("sender")
    sender = str(raw_sender).strip() if raw_sender is not None else ""

    if len(sender) > 1024:
        return jsonify({
            "is_valid": False,
            "error": "Sender header exceeds maximum permitted length (1024 characters)."
        }), 400

    analysis = analyze_email(email_body.strip(), sender if sender else None)
    result = evaluate_artifact(analysis)
    return jsonify(result), 200


@main_bp.route("/api/samples", methods=["GET"])
def api_get_samples():
    """Returns synthetic demonstration scenarios for Demo Mode."""
    return jsonify({
        "status": "success",
        "samples": SAMPLES
    }), 200
