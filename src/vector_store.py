import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional
import uuid
import json
# Conditional imports for different execution contexts
try:
    # When running as module
    from .schema import SecurityField, SecurityChunk, PolicyLevel
    from .security_data import get_security_fields
except ImportError:
    # When running directly
    from schema import SecurityField, SecurityChunk, PolicyLevel
    from security_data import get_security_fields


class KubernetesSecurityVectorStore:
    """Vector store for Kubernetes Pod security configuration guidance"""
    
    def __init__(self, persist_directory: str = "./chroma_db"):
        """Initialize the vector store with ChromaDB"""
        # Disable telemetry completely to avoid warnings
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Create or get collection
        self.collection = self.client.get_or_create_collection(
            name="kubernetes_security",
            metadata={"description": "Kubernetes Pod Security Standards and guidance"}
        )
        
    def create_chunks_from_fields(self, security_fields: List[SecurityField]) -> List[SecurityChunk]:
        """Convert security fields into chunks for vector storage"""
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
            """.strip()
            
            chunks.append(SecurityChunk(
                id=f"{field.field_name}_main_{uuid.uuid4().hex[:8]}",
                content=main_content,
                metadata={
                    "field_name": field.field_name,
                    "field_path": field.field_path,
                    "policy_level": field.policy_level.value,
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
            
            # Create YAML example chunk if available
            if field.yaml_example:
                example_content = f"""
Field: {field.field_name}
YAML Example:
{field.yaml_example}
                """.strip()
                
                chunks.append(SecurityChunk(
                    id=f"{field.field_name}_example_{uuid.uuid4().hex[:8]}",
                    content=example_content,
                    metadata={
                        "field_name": field.field_name,
                        "field_path": field.field_path,
                        "policy_level": field.policy_level.value,
                        "version_added": field.version_added or "Unknown",
                        "deprecated_in": field.deprecated_in or "Not deprecated",
                        "has_example": True,
                        "source_document": field.source_document,
                        "chunk_type": "example"
                    },
                    field_name=field.field_name,
                    policy_level=field.policy_level,
                    version_added=field.version_added,
                    deprecated_in=field.deprecated_in,
                    has_example=True,
                    source_document=field.source_document,
                    tags=["example", "yaml"]
                ))
            
            # Create pitfalls chunk
            if field.common_pitfalls:
                pitfalls_content = f"""
Field: {field.field_name}
Common Pitfalls:
{chr(10).join(f'- {pitfall}' for pitfall in field.common_pitfalls)}
                """.strip()
                
                chunks.append(SecurityChunk(
                    id=f"{field.field_name}_pitfalls_{uuid.uuid4().hex[:8]}",
                    content=pitfalls_content,
                    metadata={
                        "field_name": field.field_name,
                        "field_path": field.field_path,
                        "policy_level": field.policy_level.value,
                        "version_added": field.version_added or "Unknown",
                        "deprecated_in": field.deprecated_in or "Not deprecated",
                        "has_example": False,
                        "source_document": field.source_document,
                        "chunk_type": "pitfalls"
                    },
                    field_name=field.field_name,
                    policy_level=field.policy_level,
                    version_added=field.version_added,
                    deprecated_in=field.deprecated_in,
                    has_example=False,
                    source_document=field.source_document,
                    tags=["pitfalls", "common_mistakes"]
                ))
            
            # Create remediation chunk
            if field.remediation_steps:
                remediation_content = f"""
Field: {field.field_name}
Remediation Steps:
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(field.remediation_steps))}
                """.strip()
                
                chunks.append(SecurityChunk(
                    id=f"{field.field_name}_remediation_{uuid.uuid4().hex[:8]}",
                    content=remediation_content,
                    metadata={
                        "field_name": field.field_name,
                        "field_path": field.field_path,
                        "policy_level": field.policy_level.value,
                        "version_added": field.version_added or "Unknown",
                        "deprecated_in": field.deprecated_in or "Not deprecated",
                        "has_example": False,
                        "source_document": field.source_document,
                        "chunk_type": "remediation"
                    },
                    field_name=field.field_name,
                    policy_level=field.policy_level,
                    version_added=field.version_added,
                    deprecated_in=field.deprecated_in,
                    has_example=False,
                    source_document=field.source_document,
                    tags=["remediation", "fixes"]
                ))
        
        return chunks
    
    def add_chunks_to_store(self, chunks: List[SecurityChunk]) -> None:
        """Add chunks to the vector store"""
        if not chunks:
            return
            
        documents = []
        metadatas = []
        ids = []
        
        for chunk in chunks:
            documents.append(chunk.content)
            metadatas.append(chunk.metadata)
            ids.append(chunk.id)
        
        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"Added {len(chunks)} chunks to vector store")
    
    def search(self, query: str, n_results: int = 5, 
               policy_level: Optional[PolicyLevel] = None,
               field_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for relevant security information"""
        where_filter = {}
        
        if policy_level:
            where_filter["policy_level"] = policy_level.value
            
        if field_name:
            where_filter["field_name"] = field_name
        
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter if where_filter else None
        )
        
        return [
            {
                "id": results["ids"][0][i],
                "content": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i] if "distances" in results else None
            }
            for i in range(len(results["ids"][0]))
        ]
    
    def get_by_field_name(self, field_name: str) -> List[Dict[str, Any]]:
        """Get all chunks for a specific field"""
        results = self.collection.get(
            where={"field_name": field_name}
        )
        
        return [
            {
                "id": results["ids"][i],
                "content": results["documents"][i],
                "metadata": results["metadatas"][i]
            }
            for i in range(len(results["ids"]))
        ]
    
    def get_by_policy_level(self, policy_level: PolicyLevel) -> List[Dict[str, Any]]:
        """Get all chunks for a specific policy level"""
        results = self.collection.get(
            where={"policy_level": policy_level.value}
        )
        
        return [
            {
                "id": results["ids"][i],
                "content": results["documents"][i],
                "metadata": results["metadatas"][i]
            }
            for i in range(len(results["ids"]))
        ]
    
    def initialize_database(self) -> None:
        """Initialize the database with security fields"""
        print("Initializing Kubernetes security vector database...")
        
        # Get security fields
        security_fields = get_security_fields()
        
        # Convert to chunks
        chunks = self.create_chunks_from_fields(security_fields)
        
        # Add to vector store
        self.add_chunks_to_store(chunks)
        
        print(f"Database initialized with {len(security_fields)} security fields and {len(chunks)} chunks")


def create_vector_store() -> KubernetesSecurityVectorStore:
    """Create and initialize the vector store"""
    store = KubernetesSecurityVectorStore()
    store.initialize_database()
    return store 