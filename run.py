#!/usr/bin/env python3
"""Run CYBERNEXUS locally or execute seed-demo."""
import sys
from app import create_app
from app.seed import seed_demo

app = create_app()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed-demo":
        with app.app_context():
            seed_demo()
        print("Demo data inserted. Sign in at http://127.0.0.1:5000/login")
    else:
        app.run(host="127.0.0.1", port=5000, debug=False)
