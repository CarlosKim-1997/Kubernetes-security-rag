#!/usr/bin/env python3
"""
Database Build Script for Versioned Kubernetes Security Vector Store

This script:
1. Crawls Kubernetes documentation for multiple versions
2. Builds version-specific collections
3. Creates common collection with shared information
4. Initializes the complete vector store
"""

import os
import sys
import argparse
from typing import List, Dict, Any
import time

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from crawler import kubernetes_crawler, version_manager
from versioned_vector_store import versioned_vector_store
from security_data import get_security_fields
from schema import SecurityField, SecurityChunk, PolicyLevel


def build_common_collection() -> None:
    """Build common collection with shared security information"""
    print("🔧 Building Common Collection")
    print("=" * 50)
    
    # Get security fields
    security_fields = get_security_fields()
    
    # Create common chunks (shared across all versions)
    common_chunks = create_common_chunks(security_fields)
    
    # Add to common collection
    versioned_vector_store.add_common_chunks(common_chunks)
    
    print(f"✅ Common collection built with {len(common_chunks)} chunks")


def create_common_chunks(security_fields: List[SecurityField]) -> List[SecurityChunk]:
    """Create chunks for common collection (shared across versions)"""
    import uuid
    
    chunks = []
    
    for field in security_fields:
        # Create general description chunk (version-agnostic)
        general_content = f"""
Field: {field.field_name}
Path: {field.field_path}
Description: {field.description}
Security Impact: {field.security_impact}
Policy Level: {field.policy_level.value}
Default Value: {field.default_value or 'Not specified'}
Acceptable Values: {', '.join(field.acceptable_values)}
General Information: This field applies to multiple Kubernetes versions
        """.strip()
        
        chunks.append(SecurityChunk(
            id=f"common_{field.field_name}_{uuid.uuid4().hex[:8]}",
            content=general_content,
            metadata={
                "field_name": field.field_name,
                "field_path": field.field_path,
                "policy_level": field.policy_level.value,
                "version": "common",
                "version_added": field.version_added or "Unknown",
                "deprecated_in": field.deprecated_in or "Not deprecated",
                "has_example": False,
                "source_document": field.source_document,
                "chunk_type": "description",
                "collection_type": "common"
            },
            field_name=field.field_name,
            policy_level=field.policy_level,
            version_added=field.version_added,
            deprecated_in=field.deprecated_in,
            has_example=False,
            source_document=field.source_document,
            tags=["description", "security_impact", "common"]
        ))
        
        # Add common pitfalls and remediation
        if field.common_pitfalls:
            pitfalls_content = f"""
Field: {field.field_name}
Common Pitfalls (All Versions):
{chr(10).join(f'- {pitfall}' for pitfall in field.common_pitfalls)}
            """.strip()
            
            chunks.append(SecurityChunk(
                id=f"common_{field.field_name}_pitfalls_{uuid.uuid4().hex[:8]}",
                content=pitfalls_content,
                metadata={
                    "field_name": field.field_name,
                    "field_path": field.field_path,
                    "policy_level": field.policy_level.value,
                    "version": "common",
                    "version_added": field.version_added or "Unknown",
                    "deprecated_in": field.deprecated_in or "Not deprecated",
                    "has_example": False,
                    "source_document": field.source_document,
                    "chunk_type": "pitfalls",
                    "collection_type": "common"
                },
                field_name=field.field_name,
                policy_level=field.policy_level,
                version_added=field.version_added,
                deprecated_in=field.deprecated_in,
                has_example=False,
                source_document=field.source_document,
                tags=["pitfalls", "common_mistakes", "common"]
            ))
    
    return chunks


def build_version_collections(versions: List[str], max_pages_per_version: int = 20) -> None:
    """Build version-specific collections"""
    print(f"🔧 Building Version Collections for {versions}")
    print("=" * 50)
    
    for version in versions:
        print(f"\n📦 Building collection for version {version}")
        
        # Initialize version database
        versioned_vector_store.initialize_version_database(version)
        
        # Crawl documentation for this version
        print(f"🕷️ Crawling documentation for version {version}...")
        try:
            content_list = kubernetes_crawler.crawl_version(version, max_pages_per_version)
            
            if content_list:
                # Add crawled content to docs collection
                versioned_vector_store.add_crawled_content(content_list)
                print(f"✅ Added {len(content_list)} pages for version {version}")
            else:
                print(f"⚠️ No content crawled for version {version}")
                
        except Exception as e:
            print(f"❌ Error crawling version {version}: {e}")
        
        # Small delay between versions
        time.sleep(2)
    
    print(f"✅ Version collections built for {len(versions)} versions")


def build_documentation_collection(versions: List[str], max_pages_per_version: int = 30) -> None:
    """Build comprehensive documentation collection"""
    print("📚 Building Documentation Collection")
    print("=" * 50)
    
    all_content = []
    
    for version in versions:
        print(f"🕷️ Crawling docs for version {version}...")
        try:
            content_list = kubernetes_crawler.crawl_version(version, max_pages_per_version)
            all_content.extend(content_list)
            print(f"✅ Crawled {len(content_list)} pages for version {version}")
        except Exception as e:
            print(f"❌ Error crawling version {version}: {e}")
        
        time.sleep(1)  # Be respectful to the server
    
    # Add all content to docs collection
    if all_content:
        versioned_vector_store.add_crawled_content(all_content)
        print(f"✅ Documentation collection built with {len(all_content)} pages")
    else:
        print("⚠️ No documentation content was crawled")


def show_statistics() -> None:
    """Show database statistics"""
    print("\n📊 Database Statistics")
    print("=" * 50)
    
    stats = versioned_vector_store.get_collection_statistics()
    
    print(f"Common Collection: {stats['common_collection']['count']} chunks")
    print(f"Documentation Collection: {stats['docs_collection']['count']} chunks")
    
    print("\nVersion Collections:")
    for version, info in stats['version_collections'].items():
        print(f"  Version {version}: {info['count']} chunks")


def main():
    """Main build function"""
    parser = argparse.ArgumentParser(description="Build versioned Kubernetes security database")
    parser.add_argument("--versions", nargs="+", 
                       default=["1.25", "1.28"],
                       help="Kubernetes versions to build (default: 1.25 1.28)")
    parser.add_argument("--max-pages", type=int, default=20,
                       help="Maximum pages to crawl per version (default: 20)")
    parser.add_argument("--reset", action="store_true",
                       help="Reset all collections before building")
    parser.add_argument("--common-only", action="store_true",
                       help="Build only common collection")
    parser.add_argument("--docs-only", action="store_true",
                       help="Build only documentation collection")
    
    args = parser.parse_args()
    
    print("🚀 Kubernetes Versioned Security Database Builder")
    print("=" * 60)
    print(f"Versions: {args.versions}")
    print(f"Max pages per version: {args.max_pages}")
    print(f"Reset collections: {args.reset}")
    print("=" * 60)
    
    # Reset if requested
    if args.reset:
        print("🔄 Resetting all collections...")
        versioned_vector_store.reset_all_collections()
        print("✅ Collections reset")
    
    try:
        # Build common collection
        if not args.docs_only:
            build_common_collection()
        
        # Build version collections
        if not args.common_only and not args.docs_only:
            build_version_collections(args.versions, args.max_pages)
        
        # Build documentation collection
        if not args.common_only:
            build_documentation_collection(args.versions, args.max_pages)
        
        # Show statistics
        show_statistics()
        
        print("\n✅ Database build completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during database build: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        # Clean up
        kubernetes_crawler.close()


if __name__ == "__main__":
    main() 