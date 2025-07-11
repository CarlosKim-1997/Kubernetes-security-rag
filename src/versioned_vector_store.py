import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional, Union
import uuid
import json
# Conditional imports for different execution contexts
try:
    # When running as module
    from .schema import SecurityField, SecurityChunk, PolicyLevel, PolicyType
    from .security_data import get_security_fields
    from .crawler import ParsedContent, content_parser, version_manager
except ImportError:
    # When running directly
    from schema import SecurityField, SecurityChunk, PolicyLevel, PolicyType
    from security_data import get_security_fields
    from crawler import ParsedContent, content_parser, version_manager


class VersionedKubernetesVectorStore:
    """
    Version-aware vector store for Kubernetes security documentation
    Supports version-specific collections and common database
    """
    
    def __init__(self, persist_directory: str = "./chroma_db"):
        """Initialize the versioned vector store with ChromaDB"""
        # Disable telemetry completely to avoid warnings
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Create collections for different purposes
        self.common_collection = self.client.get_or_create_collection(
            name="kubernetes_security_common",
            metadata={"description": "Common Kubernetes security information across all versions"}
        )
        
        # Version-specific collections will be created on demand
        self.version_collections: Dict[str, chromadb.Collection] = {}
        
        # Collection for crawled documentation
        self.docs_collection = self.client.get_or_create_collection(
            name="kubernetes_docs",
            metadata={"description": "Crawled Kubernetes documentation"}
        )
    
    def get_version_collection(self, version: str) -> chromadb.Collection:
        """Get or create a version-specific collection"""
        if version not in self.version_collections:
            collection_name = f"kubernetes_security_v{version.replace('.', '_')}"
            self.version_collections[version] = self.client.get_or_create_collection(
                name=collection_name,
                metadata={
                    "description": f"Kubernetes security information for version {version}",
                    "version": version
                }
            )
        return self.version_collections[version]
    
    def add_crawled_content(self, content_list: List[ParsedContent]) -> None:
        """Add crawled content to the documentation collection"""
        if not content_list:
            return
        
        documents = []
        metadatas = []
        ids = []
        
        for content in content_list:
            # Create chunks from content sections
            chunks = self._create_chunks_from_content(content)
            
            for chunk in chunks:
                documents.append(chunk["content"])
                metadatas.append(chunk["metadata"])
                ids.append(chunk["id"])
        
        if documents:
            self.docs_collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            print(f"Added {len(documents)} chunks from {len(content_list)} pages to docs collection")
    
    def _create_chunks_from_content(self, content: ParsedContent) -> List[Dict[str, Any]]:
        """Create chunks from parsed content"""
        chunks = []
        
        # Create main content chunk
        # Filter out list values from metadata
        filtered_metadata = {}
        for key, value in content.metadata.items():
            if isinstance(value, (str, int, float, bool)):
                filtered_metadata[key] = value
            elif isinstance(value, list):
                # Convert list to string for metadata
                filtered_metadata[key] = str(value)
        
        main_chunk = {
            "id": f"main_{content.url.replace('/', '_').replace(':', '_')}_{uuid.uuid4().hex[:8]}",
            "content": content.content[:2000],  # Limit content length
            "metadata": {
                "title": content.title,
                "url": content.url,
                "version": content.version,
                "content_type": "main",
                "source": "crawled_docs",
                **filtered_metadata
            }
        }
        chunks.append(main_chunk)
        
        # Create section chunks (handle both dict and str types)
        for i, section in enumerate(content.sections):
            if isinstance(section, dict):
                if section.get("content") and len(section["content"]) > 50:  # Minimum content length
                    section_chunk = {
                        "id": f"section_{content.url.replace('/', '_').replace(':', '_')}_{i}_{uuid.uuid4().hex[:8]}",
                        "content": section["content"][:1500],  # Limit section content
                        "metadata": {
                            "title": content.title,
                            "section_title": section.get("title", ""),
                            "section_level": section.get("level", 1),
                            "url": content.url,
                            "version": content.version,
                            "content_type": "section",
                            "source": "crawled_docs",
                            **filtered_metadata
                        }
                    }
                    chunks.append(section_chunk)
            elif isinstance(section, str):
                if len(section) > 50:
                    section_chunk = {
                        "id": f"section_{content.url.replace('/', '_').replace(':', '_')}_{i}_{uuid.uuid4().hex[:8]}",
                        "content": section[:1500],
                        "metadata": {
                            "title": content.title,
                            "section_title": f"Section {i+1}",
                            "section_level": 1,
                            "url": content.url,
                            "version": content.version,
                            "content_type": "section",
                            "source": "crawled_docs",
                            **filtered_metadata
                        }
                    }
                    chunks.append(section_chunk)
        
        return chunks
    
    def add_version_specific_chunks(self, chunks: List[SecurityChunk], version: str) -> None:
        """Add version-specific chunks to the appropriate collection"""
        if not chunks:
            return
        
        collection = self.get_version_collection(version)
        
        documents = []
        metadatas = []
        ids = []
        
        for chunk in chunks:
            documents.append(chunk.content)
            # Add version information to metadata
            chunk_metadata = chunk.metadata.copy()
            chunk_metadata["version"] = version
            chunk_metadata["collection_type"] = "version_specific"
            metadatas.append(chunk_metadata)
            ids.append(chunk.id)
        
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"Added {len(chunks)} chunks to version {version} collection")
    
    def add_common_chunks(self, chunks: List[SecurityChunk]) -> None:
        """Add common chunks (shared across all versions) to common collection"""
        if not chunks:
            return
        
        documents = []
        metadatas = []
        ids = []
        
        for chunk in chunks:
            documents.append(chunk.content)
            # Mark as common
            chunk_metadata = chunk.metadata.copy()
            chunk_metadata["collection_type"] = "common"
            metadatas.append(chunk_metadata)
            ids.append(chunk.id)
        
        self.common_collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"Added {len(chunks)} chunks to common collection")
    
    def search(self, query: str, 
               version: Optional[str] = None,
               n_results: int = 5,
               policy_level: Optional[PolicyLevel] = None,
               field_name: Optional[str] = None,
               include_common: bool = True,
               include_docs: bool = True) -> List[Dict[str, Any]]:
        """
        Search across multiple collections based on version and filters
        
        Args:
            query: Search query
            version: Specific Kubernetes version to search
            n_results: Number of results per collection
            policy_level: Filter by policy level
            field_name: Filter by field name
            include_common: Include common collection in search
            include_docs: Include documentation collection in search
            
        Returns:
            Combined and ranked search results
        """
        all_results = []
        
        # Search common collection
        if include_common:
            common_results = self._search_collection(
                self.common_collection, query, n_results, policy_level, field_name
            )
            all_results.extend(common_results)
        
        # Search version-specific collection
        if version:
            version_collection = self.get_version_collection(version)
            version_results = self._search_collection(
                version_collection, query, n_results, policy_level, field_name
            )
            all_results.extend(version_results)
        
        # Search documentation collection
        if include_docs:
            docs_results = self._search_collection(
                self.docs_collection, query, n_results, policy_level, field_name
            )
            all_results.extend(docs_results)
        
        # Sort by relevance score and return top results
        all_results.sort(key=lambda x: x.get("distance", 1.0), reverse=False)
        return all_results[:n_results * 2]  # Return more results since we're combining collections
    
    def _search_collection(self, collection: chromadb.Collection, 
                          query: str, n_results: int,
                          policy_level: Optional[PolicyLevel] = None,
                          field_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search a specific collection with filters"""
        where_filter = {}
        
        if policy_level:
            where_filter["policy_level"] = policy_level.value
            
        if field_name:
            where_filter["field_name"] = field_name
        
        try:
            results = collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_filter if where_filter else None,
                include=["metadatas", "distances"]
            )
            
            # Format results
            formatted_results = []
            if results["ids"] and results["ids"][0]:
                for i, doc_id in enumerate(results["ids"][0]):
                    formatted_results.append({
                        "id": doc_id,
                        "content": results["documents"][0][i] if results["documents"] and results["documents"][0] else "",
                        "metadata": results["metadatas"][0][i] if results["metadatas"] and results["metadatas"][0] else {},
                        "distance": results["distances"][0][i] if results["distances"] and results["distances"][0] else 1.0,
                        "collection": collection.name
                    })
            
            return formatted_results
            
        except Exception as e:
            print(f"Error searching collection {collection.name}: {e}")
            return []
    
    def get_by_field_name(self, field_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get chunks by field name across collections"""
        all_results = []
        
        # Search common collection
        common_results = self._search_collection(
            self.common_collection, field_name, 10, field_name=field_name
        )
        all_results.extend(common_results)
        
        # Search version-specific collection if specified
        if version:
            version_collection = self.get_version_collection(version)
            version_results = self._search_collection(
                version_collection, field_name, 10, field_name=field_name
            )
            all_results.extend(version_results)
        
        # Search documentation collection
        docs_results = self._search_collection(
            self.docs_collection, field_name, 10, field_name=field_name
        )
        all_results.extend(docs_results)
        
        return all_results
    
    def get_by_policy_level(self, policy_level: PolicyLevel, 
                           version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get chunks by policy level across collections"""
        all_results = []
        
        # Search common collection
        common_results = self._search_collection(
            self.common_collection, policy_level.value, 10, policy_level=policy_level
        )
        all_results.extend(common_results)
        
        # Search version-specific collection if specified
        if version:
            version_collection = self.get_version_collection(version)
            version_results = self._search_collection(
                version_collection, policy_level.value, 10, policy_level=policy_level
            )
            all_results.extend(version_results)
        
        return all_results
    
    def get_collection_statistics(self) -> Dict[str, Any]:
        """Get statistics about all collections"""
        stats = {
            "common_collection": {
                "name": self.common_collection.name,
                "count": self.common_collection.count()
            },
            "docs_collection": {
                "name": self.docs_collection.name,
                "count": self.docs_collection.count()
            },
            "version_collections": {}
        }
        
        for version, collection in self.version_collections.items():
            stats["version_collections"][version] = {
                "name": collection.name,
                "count": collection.count()
            }
        
        return stats
    
    def initialize_version_database(self, version: str) -> None:
        """Initialize database for a specific version"""
        # Get security fields for this version
        security_fields = get_security_fields()
        
        # Create chunks from security fields
        chunks = self._create_chunks_from_security_fields(security_fields, version)
        
        # Add to version-specific collection
        self.add_version_specific_chunks(chunks, version)
        
        print(f"Initialized database for version {version}")
    
    def _create_chunks_from_security_fields(self, security_fields: List[SecurityField], 
                                          version: str) -> List[SecurityChunk]:
        """Create chunks from security fields with version information"""
        chunks = []
        
        for field in security_fields:
            # Create main description chunk
            main_content = f"""
Field: {field.field_name}
Path: {field.field_path}
Description: {field.description}
Security Impact: {field.security_impact}
Policy Level: {field.policy_level.value}
Default Value: {field.default_value or 'Not specified'}
Acceptable Values: {', '.join(field.acceptable_values)}
Version: {version}
            """.strip()
            
            chunks.append(SecurityChunk(
                id=f"{field.field_name}_v{version.replace('.', '_')}_main_{uuid.uuid4().hex[:8]}",
                content=main_content,
                metadata={
                    "field_name": field.field_name,
                    "field_path": field.field_path,
                    "policy_level": field.policy_level.value,
                    "version": version,
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
                tags=["description", "security_impact"]
            ))
            
            # Add other chunk types (example, pitfalls, remediation) as needed
            # ... (similar to original implementation)
        
        return chunks
    
    def reset_all_collections(self) -> None:
        """Reset all collections (use with caution)"""
        # Delete all collections
        collections_to_delete = [self.common_collection.name, self.docs_collection.name]
        collections_to_delete.extend([col.name for col in self.version_collections.values()])
        
        for collection_name in collections_to_delete:
            try:
                self.client.delete_collection(collection_name)
                print(f"Deleted collection: {collection_name}")
            except Exception as e:
                print(f"Error deleting collection {collection_name}: {e}")
        
        # Reset collections
        self.version_collections.clear()
        self.common_collection = self.client.get_or_create_collection(
            name="kubernetes_security_common",
            metadata={"description": "Common Kubernetes security information across all versions"}
        )
        self.docs_collection = self.client.get_or_create_collection(
            name="kubernetes_docs",
            metadata={"description": "Crawled Kubernetes documentation"}
        )
        
        print("All collections reset")
    
    def get_policy_type_for_version(self, version: str) -> PolicyType:
        """Get policy type for specific Kubernetes version"""
        policy_type_str = version_manager.get_policy_type_for_version(version)
        
        if policy_type_str == "PodSecurityPolicy":
            return PolicyType.POD_SECURITY_POLICY
        elif policy_type_str == "PodSecurityStandardsAlpha":
            return PolicyType.POD_SECURITY_STANDARDS_ALPHA
        else:
            return PolicyType.POD_SECURITY_STANDARDS_STABLE
    
    def get_supported_fields_for_version(self, version: str) -> Dict[str, bool]:
        """Get supported security fields for specific Kubernetes version"""
        policy_type = self.get_policy_type_for_version(version)
        
        if policy_type == PolicyType.POD_SECURITY_POLICY:
            # 1.20-1.21: PSP - 제한적 지원
            return {
                "runAsNonRoot": False,  # PSP에서는 지원 안됨
                "allowPrivilegeEscalation": False,  # PSP에서는 지원 안됨
                "readOnlyRootFilesystem": False,  # PSP에서는 지원 안됨
                "privileged": True,
                "hostPID": True,
                "hostIPC": True,
                "hostNetwork": True,
                "runAsUser": True,
                "runAsGroup": True,
                "fsGroup": True,
                "supplementalGroups": True,
                "seccompProfile": False,
                "apparmorProfile": False
            }
        elif policy_type == PolicyType.POD_SECURITY_STANDARDS_ALPHA:
            # 1.22-1.23: PSS Alpha - 일부 필드만 지원
            return {
                "runAsNonRoot": True,  # Alpha
                "allowPrivilegeEscalation": True,  # Alpha
                "readOnlyRootFilesystem": True,  # Alpha
                "privileged": True,
                "hostPID": True,
                "hostIPC": True,
                "hostNetwork": True,
                "runAsUser": True,
                "runAsGroup": True,
                "fsGroup": True,
                "supplementalGroups": True,
                "seccompProfile": False,  # 지원 안됨
                "apparmorProfile": False  # 지원 안됨
            }
        else:
            # 1.24+: PSS Stable - 모든 필드 지원
            return {
                "runAsNonRoot": True,
                "allowPrivilegeEscalation": True,
                "readOnlyRootFilesystem": True,
                "privileged": True,
                "hostPID": True,
                "hostIPC": True,
                "hostNetwork": True,
                "runAsUser": True,
                "runAsGroup": True,
                "fsGroup": True,
                "supplementalGroups": True,
                "seccompProfile": True,
                "apparmorProfile": True
            }
    
    def get_version_compatibility_info(self, version: str) -> Dict[str, Any]:
        """Get comprehensive compatibility information for a version"""
        policy_type = self.get_policy_type_for_version(version)
        supported_fields = self.get_supported_fields_for_version(version)
        
        # 버전별 특징 정보
        version_features = {
            PolicyType.POD_SECURITY_POLICY: {
                "description": "PodSecurityPolicy (PSP) - Legacy security model",
                "restricted_policy_available": False,
                "baseline_policy_available": True,
                "privileged_policy_available": True,
                "migration_recommendation": "Upgrade to 1.24+ for Pod Security Standards",
                "alternative_approach": "Use PodSecurityPolicy resources for security control"
            },
            PolicyType.POD_SECURITY_STANDARDS_ALPHA: {
                "description": "Pod Security Standards (PSS) - Alpha stage",
                "restricted_policy_available": True,
                "baseline_policy_available": True,
                "privileged_policy_available": True,
                "migration_recommendation": "Consider upgrading to 1.24+ for stable PSS",
                "alternative_approach": "Use PSS Alpha features with caution in production"
            },
            PolicyType.POD_SECURITY_STANDARDS_STABLE: {
                "description": "Pod Security Standards (PSS) - Stable",
                "restricted_policy_available": True,
                "baseline_policy_available": True,
                "privileged_policy_available": True,
                "migration_recommendation": "Current version - no migration needed",
                "alternative_approach": "Use all PSS features with confidence"
            }
        }
        
        return {
            "version": version,
            "policy_type": policy_type.value,
            "supported_fields": supported_fields,
            "features": version_features[policy_type],
            "unsupported_fields": [field for field, supported in supported_fields.items() if not supported],
            "recommended_upgrade": version_features[policy_type]["migration_recommendation"]
        }


# Global instance
versioned_vector_store = VersionedKubernetesVectorStore() 