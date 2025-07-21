import React, { useState } from 'react';
import {
  Checkbox,
  Typography,
  Box,
  Chip,
  Collapse,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  ExpandMore,
  ChevronRight,
  CheckCircle,
  RadioButtonUnchecked,
  Info,
  Warning,
  Error,
} from '@mui/icons-material';
import { CheckItem } from '../types';

interface ChecklistTreeProps {
  items: CheckItem[];
  onItemCheck: (itemId: string, isChecked: boolean) => void;
  onItemNotes: (itemId: string, notes: string) => void;
}

const getSeverityIcon = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return <Error color="error" />;
    case 'high':
      return <Warning color="warning" />;
    case 'medium':
      return <Info color="info" />;
    case 'low':
      return <Info color="action" />;
    default:
      return <Info />;
  }
};

const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'error';
    case 'high':
      return 'warning';
    case 'medium':
      return 'info';
    case 'low':
      return 'default';
    default:
      return 'default';
  }
};

const ChecklistItem: React.FC<{
  item: CheckItem;
  onCheck: (itemId: string, isChecked: boolean) => void;
  onNotes: (itemId: string, notes: string) => void;
  level?: number;
}> = ({ item, onCheck, onNotes, level = 0 }) => {
  const [expanded, setExpanded] = useState(level === 0);
  const [showSolution, setShowSolution] = useState(false);

  const handleCheck = (event: React.ChangeEvent<HTMLInputElement>) => {
    onCheck(item.id, event.target.checked);
  };

  const handleExpand = () => {
    setExpanded(!expanded);
  };

  const hasChildren = item.children && item.children.length > 0;

  return (
    <Box sx={{ ml: level * 2 }}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          p: 1,
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 1,
          mb: 1,
          backgroundColor: item.is_checked ? 'action.hover' : 'background.paper',
        }}
      >
        {hasChildren && (
          <IconButton size="small" onClick={handleExpand}>
            {expanded ? <ExpandMore /> : <ChevronRight />}
          </IconButton>
        )}
        
        <Checkbox
          checked={item.is_checked}
          onChange={handleCheck}
          icon={<RadioButtonUnchecked />}
          checkedIcon={<CheckCircle />}
          size="small"
        />
        
        <Box sx={{ flexGrow: 1, ml: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" fontWeight="medium">
              {item.title}
            </Typography>
            <Chip
              label={item.severity}
              size="small"
              color={getSeverityColor(item.severity) as any}
              icon={getSeverityIcon(item.severity)}
            />
            <Chip
              label={item.category}
              size="small"
              variant="outlined"
            />
          </Box>
          
          <Typography variant="caption" color="text.secondary">
            {item.description}
          </Typography>
          
          {item.solution_guide && (
            <Tooltip title="해결 가이드 보기">
              <IconButton
                size="small"
                onClick={() => setShowSolution(!showSolution)}
              >
                <Info />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </Box>
      
      {showSolution && item.solution_guide && (
        <Box
          sx={{
            ml: 4,
            p: 2,
            backgroundColor: 'grey.50',
            borderRadius: 1,
            mb: 1,
            border: '1px solid',
            borderColor: 'divider',
          }}
        >
          <Typography variant="subtitle2" gutterBottom>
            해결 가이드:
          </Typography>
          <Typography variant="body2" whiteSpace="pre-wrap">
            {item.solution_guide}
          </Typography>
        </Box>
      )}
      
      {expanded && hasChildren && (
        <Box>
          {item.children.map((child) => (
            <ChecklistItem
              key={child.id}
              item={child}
              onCheck={onCheck}
              onNotes={onNotes}
              level={level + 1}
            />
          ))}
        </Box>
      )}
    </Box>
  );
};

const ChecklistTree: React.FC<ChecklistTreeProps> = ({
  items,
  onItemCheck,
  onItemNotes,
}) => {
  return (
    <Box>
      {items.map((item) => (
        <ChecklistItem
          key={item.id}
          item={item}
          onCheck={onItemCheck}
          onNotes={onItemNotes}
        />
      ))}
    </Box>
  );
};

export default ChecklistTree; 