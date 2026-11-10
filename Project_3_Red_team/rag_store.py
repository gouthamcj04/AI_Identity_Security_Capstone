"""Toy retrieval over the knowledge_base/ folder.

Deliberately simple keyword overlap, not embeddings: the point of this lab is to study
what the agent does with retrieved text, not to build a production RAG pipeline.
Edit, add or replace files in knowledge_base/ to stage Project 3, item 4 (RAG poisoning)
yourself; nothing in this file writes attack content for you.
"""
import re
from pathlib import Path

KB_DIR = Path(__file__).parent / "knowledge_base"

_WORD_RE = re.compile(r"[a-z0-9]+")


def _words(text):
    return set(_WORD_RE.findall(text.lower()))


def load_documents():
    KB_DIR.mkdir(exist_ok=True)
    docs = []
    for path in sorted(KB_DIR.glob("*.txt")):
        docs.append({"name": path.name, "text": path.read_text(encoding="utf-8")})
    return docs


def retrieve(query, top_k=3):
    """Return up to top_k documents, ranked by shared words with the query.

    A document with zero overlap is never returned, so a payload only "retrieves"
    when its wording is actually relevant to what the user asked.
    """
    q_words = _words(query)
    if not q_words:
        return []
    scored = []
    for doc in load_documents():
        overlap = len(q_words & _words(doc["text"]))
        if overlap > 0:
            scored.append((overlap, doc))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [doc for _, doc in scored[:top_k]]