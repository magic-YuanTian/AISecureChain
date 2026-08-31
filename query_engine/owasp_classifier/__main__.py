"""python -m owasp_classifier → classify CLI (does not import llm in package init)."""

from owasp_classifier.llm import main

if __name__ == "__main__":
    raise SystemExit(main())
