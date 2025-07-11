#!/usr/bin/env python3
"""
Extended Versioned Kubernetes Database Builder
Supports versions 1.20-1.29 with proper policy type handling
"""

import os
import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from crawler.kubernetes_docs_crawler import KubernetesDocsCrawler
from crawler.version_manager import version_manager
from versioned_vector_store import versioned_vector_store
from security_data import get_security_fields

def build_versioned_database():
    """Build versioned database for all supported versions"""
    print("🚀 Building Extended Versioned Kubernetes Database")
    print("=" * 60)
    
    # Get all supported versions
    supported_versions = version_manager.get_supported_versions()
    print(f"📋 Supported versions: {supported_versions}")
    
    # Group versions by policy type
    psp_versions = version_manager.get_versions_by_policy_type("PodSecurityPolicy")
    pss_alpha_versions = version_manager.get_versions_by_policy_type("PodSecurityStandardsAlpha")
    pss_stable_versions = version_manager.get_versions_by_policy_type("PodSecurityStandardsStable")
    
    print(f"\n📊 Version Groups:")
    print(f"   PSP (1.20-1.21): {psp_versions}")
    print(f"   PSS Alpha (1.22-1.23): {pss_alpha_versions}")
    print(f"   PSS Stable (1.24+): {pss_stable_versions}")
    
    # Initialize crawler
    crawler = KubernetesDocsCrawler()
    
    # Build for each version group
    for version_group, versions in [
        ("PSP", psp_versions),
        ("PSS Alpha", pss_alpha_versions),
        ("PSS Stable", pss_stable_versions)
    ]:
        print(f"\n🔧 Building {version_group} versions...")
        
        for version in versions:
            print(f"\n📦 Processing version {version}...")
            
            try:
                # Get version info
                version_info = version_manager.get_version_info(version)
                if not version_info:
                    print(f"   ⚠️ Version info not found for {version}")
                    continue
                
                print(f"   Policy Type: {version_info.policy_type}")
                print(f"   Docs URL: {version_info.docs_url}")
                print(f"   Security Docs URL: {version_info.security_docs_url}")
                
                # Crawl documentation
                print(f"   🕷️ Crawling documentation...")
                crawled_content = crawler.crawl_version(version)
                
                if crawled_content:
                    print(f"   ✅ Crawled {len(crawled_content)} content items")
                    
                    # Add to vector store
                    print(f"   💾 Adding to vector store...")
                    versioned_vector_store.add_crawled_content(crawled_content)
                    
                    # Initialize version-specific database
                    print(f"   🔧 Initializing version-specific database...")
                    versioned_vector_store.initialize_version_database(version)
                    
                    print(f"   ✅ Version {version} completed successfully")
                else:
                    print(f"   ⚠️ No content crawled for version {version}")
                
            except Exception as e:
                print(f"   ❌ Error processing version {version}: {e}")
                import traceback
                traceback.print_exc()
    
    # Build common database
    print(f"\n🔧 Building common database...")
    try:
        security_fields = get_security_fields()
        print(f"   📋 Found {len(security_fields)} security fields")
        
        # Convert SecurityField to SecurityChunk
        from schema import SecurityChunk
        import uuid
        
        security_chunks = []
        for field in security_fields:
            chunk = SecurityChunk(
                id=f"common_{field.field_name}_{uuid.uuid4().hex[:8]}",
                content=f"""
Field: {field.field_name}
Path: {field.field_path}
Description: {field.description}
Security Impact: {field.security_impact}
Policy Level: {field.policy_level.value}
Default Value: {field.default_value or 'Not specified'}
Acceptable Values: {', '.join(field.acceptable_values)}
                """.strip(),
                metadata={
                    "field_name": field.field_name,
                    "field_path": field.field_path,
                    "policy_level": field.policy_level.value,
                    "version": "common",
                    "version_added": field.version_added or "Unknown",
                    "deprecated_in": field.deprecated_in or "Not deprecated",
                    "has_example": False,
                    "source_document": field.source_document,
                    "chunk_type": "description"
                },
                field_name=field.field_name,
                policy_level=field.policy_level,
                version_added=field.version_added,
                deprecated_in=field.deprecated_in,
                has_example=False,
                source_document=field.source_document,
                tags=["description", "security_impact", "common"]
            )
            security_chunks.append(chunk)
        
        # Add common chunks
        versioned_vector_store.add_common_chunks(security_chunks)
        print(f"   ✅ Common database completed")
        
    except Exception as e:
        print(f"   ❌ Error building common database: {e}")
        import traceback
        traceback.print_exc()
    
    # Print final statistics
    print(f"\n📊 Final Database Statistics")
    print("=" * 60)
    
    try:
        stats = versioned_vector_store.get_collection_statistics()
        
        print(f"Common Collection: {stats['common_collection']['count']} items")
        print(f"Documentation Collection: {stats['docs_collection']['count']} items")
        
        print(f"\nVersion Collections:")
        for version, collection_stats in stats['version_collections'].items():
            policy_type = version_manager.get_policy_type_for_version(version)
            print(f"   {version} ({policy_type}): {collection_stats['count']} items")
        
    except Exception as e:
        print(f"Error getting statistics: {e}")
    
    print(f"\n🎉 Extended versioned database build completed!")

def main():
    """Main function"""
    # Set environment variables
    os.environ["PYTHONPATH"] = str(Path(__file__).parent.parent / "src")
    
    # Run the build
    build_versioned_database()

if __name__ == "__main__":
    main() 