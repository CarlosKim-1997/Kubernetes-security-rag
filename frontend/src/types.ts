export interface UserContext {
  kubernetes_version?: string;
  cloud_platform?: string;
  cluster_type?: string;
  security_level?: string;
}

export interface CheckItem {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  children: CheckItem[];
  solution_guide: string;
  related_docs: string[];
  metadata: Record<string, any>;
  is_checked: boolean;
  user_notes: string;
}

export interface ProblemTree {
  root: CheckItem;
  created_at: string;
  user_context: Record<string, any>;
  metadata: Record<string, any>;
}

export interface ProgressSummary {
  total_items: number;
  checked_items: number;
  progress_percentage: number;
  critical_items: number;
  categories: Record<string, number>;
}

export interface ChecklistResponse {
  checklist: ProblemTree;
  progress_summary: ProgressSummary;
}

export interface CreateChecklistRequest {
  user_input: string;
  error_logs?: string;
  user_context?: UserContext;
}

export interface UpdateProgressRequest {
  checklist: ProblemTree;
  item_id: string;
  is_checked: boolean;
  user_notes?: string;
}

export interface NextItemResponse {
  item: CheckItem | null;
} 