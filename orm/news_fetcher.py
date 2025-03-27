import requests
import urllib3
import feedparser
import logging
from datetime import datetime
from django.core.cache import cache
from bs4 import BeautifulSoup  # For Wikipedia scraping

# Suppress InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logger = logging.getLogger(__name__)

def fetch_rss_feed(url, source_name):
    """
    Fetches live articles from an RSS feed using requests and feedparser, with error handling.
    """
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()
        feed = feedparser.parse(response.content)
        
        if feed.bozo:
            logger.error(f"Failed to parse feed from {source_name}: {feed.bozo_exception}")
            return []
        
        articles = []
        for entry in feed.entries[:5]:  # Limit to top 5 articles
            articles.append({
                'title': entry.title,
                'url': entry.link,
                'snippet': entry.summary if 'summary' in entry else '',
                'source': source_name,
                'published_at': entry.published if 'published' in entry else datetime.now().strftime('%Y-%m-%d')
            })
        return articles
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error fetching feed from {source_name}: {e}")
        return []

def fetch_google_news(query):
    """
    Fetches articles related to the query from Google News RSS.
    """
    url = f"https://news.google.com/rss/search?q={query}"
    return fetch_rss_feed(url, "Google News")

def fetch_wikipedia_info(query):
    """
    Scrapes Wikipedia for information on a given query.
    """
    url = f"https://en.wikipedia.org/wiki/{query.replace(' ', '_')}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract the introductory paragraph
        paragraphs = soup.find_all('p')
        intro_text = paragraphs[0].get_text().strip() if paragraphs else ''
        return {
            'title': f"Wikipedia - {query}",
            'url': url,
            'snippet': intro_text,
            'source': "Wikipedia",
            'published_at': datetime.now().strftime('%Y-%m-%d')
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Wikipedia info for {query}: {e}")
        return {}

def fetch_news_from_sources():
    """
    Aggregates articles from multiple RSS feeds, Google News, and Wikipedia, with caching.
    """
    cached_articles = cache.get("news_articles")
    if cached_articles:
        return cached_articles

    # Define the RSS feeds and keywords
    rss_feeds = {
        "Euro2day": "https://www.euro2day.gr/rss.ashx",
        "Naftemporiki": "https://www.naftemporiki.gr/feed/",
    }
    search_keywords = ["ΑΒΑΞ Α.Ε.", "κατασκευές", "TBM", "μετρό Αθήνα"]

    # Fetch articles from each RSS feed
    all_articles = []
    for source, url in rss_feeds.items():
        articles = fetch_rss_feed(url, source)
        filtered_articles = [
            article for article in articles
            if any(keyword in article['title'] for keyword in search_keywords)
        ]
        all_articles.extend(filtered_articles)

    # Fetch articles from Google News for relevant topics
    for keyword in search_keywords:
        all_articles.extend(fetch_google_news(keyword))

    # Fetch introductory information from Wikipedia
    wikipedia_topics = ["Avax S.A.", "Construction in Greece", "Tunnel Boring Machine"]
    for topic in wikipedia_topics:
        wiki_article = fetch_wikipedia_info(topic)
        if wiki_article:
            all_articles.append(wiki_article)

    # Cache the combined articles for 30 minutes
    cache.set("news_articles", all_articles, 1800)
    return all_articles
