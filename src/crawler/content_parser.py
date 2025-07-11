from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import re
import html
from bs4 import BeautifulSoup
import markdown
from urllib.parse import urljoin, urlparse


@dataclass
class ParsedContent:
    """Parsed content structure"""
    title: str
    content: str
    sections: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    url: str
    version: str


@dataclass
class ContentSection:
    """Content section structure"""
    title: str
    content: str
    level: int
    subsections: List['ContentSection']
    metadata: Dict[str, Any]


class ContentParser:
    """
    Parses HTML and Markdown content from Kubernetes documentation
    """
    
    def __init__(self):
        self.section_patterns = [
            r'^#{1,6}\s+(.+)$',  # Markdown headers
            r'^<h[1-6][^>]*>(.+?)</h[1-6]>$',  # HTML headers
        ]
        
        self.code_block_patterns = [
            r'```(\w+)?\n(.*?)\n```',  # Markdown code blocks
            r'<pre><code[^>]*>(.*?)</code></pre>',  # HTML code blocks
        ]
        
        self.table_patterns = [
            r'\|(.+)\|',  # Markdown tables
            r'<table[^>]*>(.*?)</table>',  # HTML tables
        ]
    
    def parse_html_content(self, html_content: str, url: str, version: str) -> ParsedContent:
        """Parse HTML content and extract structured information"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract title
        title = self._extract_title(soup)
        
        # Extract main content
        main_content = self._extract_main_content(soup)
        
        # Parse sections
        sections = self._parse_html_sections(soup)
        
        # Extract metadata
        metadata = self._extract_metadata(soup, url, version)
        
        return ParsedContent(
            title=title,
            content=main_content,
            sections=sections,
            metadata=metadata,
            url=url,
            version=version
        )
    
    def parse_markdown_content(self, markdown_content: str, url: str, version: str) -> ParsedContent:
        """Parse Markdown content and extract structured information"""
        # Convert markdown to HTML for easier parsing
        html_content = markdown.markdown(markdown_content)
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract title
        title = self._extract_title_from_markdown(markdown_content)
        
        # Parse sections
        sections = self._parse_markdown_sections(markdown_content)
        
        # Extract metadata
        metadata = self._extract_metadata_from_markdown(markdown_content, url, version)
        
        return ParsedContent(
            title=title,
            content=markdown_content,
            sections=sections,
            metadata=metadata,
            url=url,
            version=version
        )
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract title from HTML content"""
        # Try different title selectors
        title_selectors = [
            'h1',
            'title',
            '[class*="title"]',
            '[id*="title"]'
        ]
        
        for selector in title_selectors:
            title_elem = soup.select_one(selector)
            if title_elem:
                return title_elem.get_text().strip()
        
        return "Untitled"
    
    def _extract_title_from_markdown(self, content: str) -> str:
        """Extract title from Markdown content"""
        lines = content.split('\n')
        for line in lines:
            if line.startswith('# '):
                return line[2:].strip()
        return "Untitled"
    
    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """Extract main content from HTML"""
        # Remove navigation, sidebar, footer
        for selector in ['nav', '.sidebar', '.navigation', 'footer', '.footer']:
            for elem in soup.select(selector):
                elem.decompose()
        
        # Try to find main content area
        main_selectors = [
            'main',
            '[role="main"]',
            '.content',
            '.main-content',
            'article'
        ]
        
        for selector in main_selectors:
            main_elem = soup.select_one(selector)
            if main_elem:
                return main_elem.get_text().strip()
        
        # Fallback to body content
        return soup.get_text().strip()
    
    def _parse_html_sections(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Parse HTML sections"""
        sections = []
        
        # Find all headers
        headers = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        
        for header in headers:
            level = int(header.name[1])
            title = header.get_text().strip()
            
            # Get content until next header of same or higher level
            content = self._extract_section_content(header, level)
            
            sections.append({
                'title': title,
                'level': level,
                'content': content,
                'type': 'section'
            })
        
        return sections
    
    def _parse_markdown_sections(self, content: str) -> List[Dict[str, Any]]:
        """Parse Markdown sections"""
        sections = []
        lines = content.split('\n')
        
        current_section = None
        current_content = []
        
        for line in lines:
            # Check if line is a header
            header_match = re.match(r'^(#{1,6})\s+(.+)$', line)
            
            if header_match:
                # Save previous section
                if current_section:
                    current_section['content'] = '\n'.join(current_content).strip()
                    sections.append(current_section)
                
                # Start new section
                level = len(header_match.group(1))
                title = header_match.group(2).strip()
                
                current_section = {
                    'title': title,
                    'level': level,
                    'content': '',
                    'type': 'section'
                }
                current_content = []
            else:
                if current_section:
                    current_content.append(line)
        
        # Add last section
        if current_section:
            current_section['content'] = '\n'.join(current_content).strip()
            sections.append(current_section)
        
        return sections
    
    def _extract_section_content(self, header_elem, level: int) -> str:
        """Extract content for a section until next header of same or higher level"""
        content_parts = []
        current = header_elem.next_sibling
        
        while current:
            if hasattr(current, 'name'):
                if current.name and current.name.startswith('h') and len(current.name) == 2:
                    current_level = int(current.name[1])
                    if current_level <= level:
                        break
                content_parts.append(str(current))
            else:
                content_parts.append(str(current))
            
            current = current.next_sibling
        
        return ''.join(content_parts).strip()
    
    def _extract_metadata(self, soup: BeautifulSoup, url: str, version: str) -> Dict[str, Any]:
        """Extract metadata from HTML content"""
        metadata: Dict[str, Any] = {
            'url': url,
            'version': version,
            'language': 'en',
            'content_type': 'html'
        }
        
        # Extract meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', meta.get('property', ''))
            content = meta.get('content', '')
            
            if name and content:
                metadata[name] = content
        
        # Extract links
        links = soup.find_all('a', href=True)
        metadata['links'] = [str(link['href']) for link in links]
        
        # Extract images
        images = soup.find_all('img', src=True)
        metadata['images'] = [str(img['src']) for img in images]
        
        return metadata
    
    def _extract_metadata_from_markdown(self, content: str, url: str, version: str) -> Dict[str, Any]:
        """Extract metadata from Markdown content"""
        metadata: Dict[str, Any] = {
            'url': url,
            'version': version,
            'language': 'en',
            'content_type': 'markdown'
        }
        
        # Extract front matter if present
        front_matter_match = re.match(r'^---\n(.*?)\n---\n', content, re.DOTALL)
        if front_matter_match:
            front_matter = front_matter_match.group(1)
            for line in front_matter.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()
        
        # Extract links
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        links = re.findall(link_pattern, content)
        metadata['links'] = [link[1] for link in links]
        
        # Extract images
        image_pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
        images = re.findall(image_pattern, content)
        metadata['images'] = [img[1] for img in images]
        
        return metadata
    
    def extract_code_blocks(self, content: str) -> List[Dict[str, str]]:
        """Extract code blocks from content"""
        code_blocks = []
        
        # Markdown code blocks
        markdown_pattern = r'```(\w+)?\n(.*?)\n```'
        for match in re.finditer(markdown_pattern, content, re.DOTALL):
            language = match.group(1) or 'text'
            code = match.group(2)
            code_blocks.append({
                'language': language,
                'code': code,
                'type': 'markdown'
            })
        
        # HTML code blocks
        html_pattern = r'<pre><code[^>]*>(.*?)</code></pre>'
        for match in re.finditer(html_pattern, content, re.DOTALL):
            code = html.unescape(match.group(1))
            code_blocks.append({
                'language': 'text',
                'code': code,
                'type': 'html'
            })
        
        return code_blocks
    
    def extract_tables(self, content: str) -> List[Dict[str, Any]]:
        """Extract tables from content"""
        tables = []
        
        # Markdown tables
        table_pattern = r'(\|.*\|(?:\n\|.*\|)+)'
        for match in re.finditer(table_pattern, content):
            table_text = match.group(1)
            table_data = self._parse_markdown_table(table_text)
            tables.append({
                'type': 'markdown',
                'data': table_data,
                'raw': table_text
            })
        
        return tables
    
    def _parse_markdown_table(self, table_text: str) -> List[List[str]]:
        """Parse markdown table into structured data"""
        lines = table_text.strip().split('\n')
        if len(lines) < 2:
            return []
        
        # Skip separator line (second line with |---|)
        data_lines = [lines[0]] + lines[2:]
        
        table_data = []
        for line in data_lines:
            if line.strip():
                # Split by | and clean up
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                table_data.append(cells)
        
        return table_data
    
    def clean_content(self, content: str) -> str:
        """Clean and normalize content"""
        # Remove extra whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove HTML tags
        content = re.sub(r'<[^>]+>', '', content)
        
        # Decode HTML entities
        content = html.unescape(content)
        
        return content.strip()


# Global instance
content_parser = ContentParser() 