"""
Root entry point to execute the Phishing Awareness Analyzer development server.
"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    # Default debug mode to False for security; opt-in explicitly via FLASK_DEBUG=1
    debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")

    print("=" * 70)
    print("   Phishing Awareness Analyzer (Local Static Evaluation)")
    print(f"   Server running at: http://{host}:{port}")
    print("   Security: Strictly local analysis, 0 external network requests.")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)
