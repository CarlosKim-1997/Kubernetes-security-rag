import requests
import time
import logging
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

from .version_manager import VersionManager, version_manager
from .content_parser import ContentParser, content_parser, ParsedContent
from .static_content_generator import static_content_generator


class KubernetesDocsCrawler:
    """
    Crawls Kubernetes official documentation for different versions
    """
    
    def __init__(self, 
                 base_url: str = "https://kubernetes.io",
                 delay: float = 1.0,
                 max_retries: int = 3,
                 timeout: int = 30):
        """
        Initialize the crawler
        
        Args:
            base_url: Base URL for Kubernetes documentation
            delay: Delay between requests in seconds
            max_retries: Maximum number of retries for failed requests
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.delay = delay
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = requests.Session()
        self.visited_urls: Set[str] = set()
        
        # Set up session headers
        self.session.headers.update({
            'User-Agent': 'Kubernetes-Docs-Crawler/1.0 (Educational Project)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def crawl_version(self, version: str, max_pages: int = 50) -> List[ParsedContent]:
        """
        Crawl documentation for a specific Kubernetes version
        
        Args:
            version: Kubernetes version (e.g., "1.25")
            max_pages: Maximum number of pages to crawl
            
        Returns:
            List of parsed content
        """
        if not version_manager.is_version_supported(version):
            self.logger.error(f"Version {version} is not supported")
            return []
        
        self.logger.info(f"Starting crawl for Kubernetes version {version}")
        
        # For older versions (1.20, 1.21), use static content instead of crawling
        if version in ['1.20', '1.21']:
            self.logger.info(f"Using static content for version {version}")
            return static_content_generator.generate_content_for_version(version)
        
        # Get URLs for this version
        urls = version_manager.get_version_urls(version)
        if not urls:
            self.logger.error(f"No URLs found for version {version}")
            return []
        
        # Start with security-related pages
        security_urls = []
        
        # Add version-specific security URLs for newer versions
        security_urls = [
            urls.get("pod_security_standards"),
            urls.get("security_context"),
            urls.get("rbac"),
            urls.get("network_policies"),
            urls.get("secrets"),
            urls.get("service_accounts")
        ]
        
        # Filter out None values
        security_urls = [url for url in security_urls if url]
        
        crawled_content = []
        visited_count = 0
        
        # Crawl security pages first
        for url in security_urls:
            if visited_count >= max_pages:
                break
            
            try:
                content = self._crawl_single_page(url, version)
                if content:
                    crawled_content.append(content)
                    visited_count += 1
                    self.logger.info(f"Crawled security page: {url}")
                
                time.sleep(self.delay)
                
            except Exception as e:
                self.logger.error(f"Error crawling {url}: {e}")
        
        # If we haven't reached max_pages, crawl additional pages
        if visited_count < max_pages:
            additional_content = self._crawl_additional_pages(
                version, max_pages - visited_count
            )
            crawled_content.extend(additional_content)
        
        self.logger.info(f"Completed crawl for version {version}. "
                        f"Total pages: {len(crawled_content)}")
        
        return crawled_content
    
    def _crawl_single_page(self, url: str, version: str) -> Optional[ParsedContent]:
        """
        Crawl a single page and return parsed content
        
        Args:
            url: URL to crawl
            version: Kubernetes version
            
        Returns:
            Parsed content or None if failed
        """
        if url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                
                # Check if it's HTML content
                content_type = response.headers.get('content-type', '')
                if 'text/html' in content_type:
                    return content_parser.parse_html_content(
                        response.text, url, version
                    )
                elif 'text/markdown' in content_type or url.endswith('.md'):
                    return content_parser.parse_markdown_content(
                        response.text, url, version
                    )
                else:
                    self.logger.warning(f"Unsupported content type: {content_type} for {url}")
                    return None
                
            except requests.RequestException as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.delay * (attempt + 1))
                else:
                    self.logger.error(f"Failed to crawl {url} after {self.max_retries} attempts")
                    return None
        
        return None
    
    def _crawl_additional_pages(self, version: str, max_pages: int) -> List[ParsedContent]:
        """
        Crawl additional pages by following links from security pages
        
        Args:
            version: Kubernetes version
            max_pages: Maximum number of additional pages to crawl
            
        Returns:
            List of parsed content
        """
        additional_content = []
        
        # Get the main docs URL for this version
        docs_url = version_manager.get_docs_url(version)
        if not docs_url:
            return additional_content
        
        # Try to find additional security-related pages
        try:
            response = self.session.get(docs_url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find links to security-related pages
            security_keywords = [
                'security', 'pod', 'rbac', 'network-policy', 
                'secret', 'configmap', 'service-account',
                'authentication', 'authorization', 'admission'
            ]
            
            links = soup.find_all('a', href=True)
            security_links = []
            
            for link in links:
                href = link.get('href', '')
                link_text = link.get_text().lower()
                
                # Check if link is security-related
                if any(keyword in href.lower() or keyword in link_text 
                      for keyword in security_keywords):
                    full_url = urljoin(docs_url, href)
                    if full_url.startswith(self.base_url):
                        security_links.append(full_url)
            
            # Crawl security links (up to max_pages)
            for link in security_links[:max_pages]:
                try:
                    content = self._crawl_single_page(link, version)
                    if content:
                        additional_content.append(content)
                        self.logger.info(f"Crawled additional page: {link}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.error(f"Error crawling additional page {link}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error crawling additional pages: {e}")
        
        return additional_content
    
    def crawl_multiple_versions(self, versions: List[str], 
                               max_pages_per_version: int = 50) -> Dict[str, List[ParsedContent]]:
        """
        Crawl documentation for multiple Kubernetes versions
        
        Args:
            versions: List of Kubernetes versions to crawl
            max_pages_per_version: Maximum pages per version
            
        Returns:
            Dictionary mapping version to list of parsed content
        """
        results = {}
        
        for version in versions:
            self.logger.info(f"Starting crawl for version {version}")
            content = self.crawl_version(version, max_pages_per_version)
            results[version] = content
            
            # Reset visited URLs for next version
            self.visited_urls.clear()
        
        return results
    
    def get_crawl_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the crawling process
        
        Returns:
            Dictionary with crawl statistics
        """
        return {
            'total_visited_urls': len(self.visited_urls),
            'visited_urls': list(self.visited_urls),
            'supported_versions': version_manager.get_supported_versions(),
            'lts_versions': version_manager.get_lts_versions()
        }
    
    def save_crawled_content(self, content_list: List[ParsedContent], 
                           output_file: str) -> None:
        """
        Save crawled content to a file
        
        Args:
            content_list: List of parsed content
            output_file: Output file path
        """
        import json
        
        # Convert to serializable format
        serializable_content = []
        for content in content_list:
            serializable_content.append({
                'title': content.title,
                'content': content.content,
                'sections': content.sections,
                'metadata': content.metadata,
                'url': content.url,
                'version': content.version
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_content, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Saved {len(content_list)} pages to {output_file}")
    
    def close(self):
        """Close the crawler session"""
        self.session.close()


# Global instance
kubernetes_crawler = KubernetesDocsCrawler() 