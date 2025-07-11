import React, { useState, useEffect } from 'react';
import {
  Alert,
  Card,
  CardContent,
  CardHeader,
  List,
  ListItem,
  ListItemText,
  Chip,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Box,
  Button,
  Paper
} from '@mui/material';
import {
  Info as InfoIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  ExpandMore as ExpandMoreIcon
} from '@mui/icons-material';

interface VersionGuidanceProps {
  version: string;
  onClose?: () => void;
}

interface GuidanceData {
  version: string;
  policy_type: string;
  title: string;
  description: string;
  key_features: string[];
  limitations: string[];
  recommendations: string[];
  migration_steps: string[];
  examples: string[];
  error?: string;
}

const VersionGuidance: React.FC<VersionGuidanceProps> = ({ version, onClose }) => {
  const [guidance, setGuidance] = useState<GuidanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchVersionGuidance();
  }, [version]);

  const fetchVersionGuidance = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`/api/rag/version-guidance?version=${version}`);
      if (!response.ok) {
        throw new Error('버전 안내문을 불러올 수 없습니다.');
      }
      
      const data = await response.json();
      setGuidance(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : '알 수 없는 오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  const getPolicyTypeColor = (policyType: string): "default" | "primary" | "secondary" | "error" | "info" | "success" | "warning" => {
    switch (policyType) {
      case 'PodSecurityPolicy':
        return 'warning';
      case 'PodSecurityStandardsAlpha':
        return 'info';
      case 'PodSecurityStandardsStable':
        return 'success';
      default:
        return 'default';
    }
  };

  const getPolicyTypeIcon = (policyType: string) => {
    switch (policyType) {
      case 'PodSecurityPolicy':
        return <WarningIcon />;
      case 'PodSecurityStandardsAlpha':
        return <InfoIcon />;
      case 'PodSecurityStandardsStable':
        return <CheckCircleIcon />;
      default:
        return <InfoIcon />;
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ textAlign: 'center', py: 2 }}>
            <Typography>버전 안내문을 불러오는 중...</Typography>
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error || guidance?.error) {
    return (
      <Alert
        severity="error"
        onClose={onClose}
        sx={{ mb: 2 }}
      >
        {error || guidance?.error}
      </Alert>
    );
  }

  if (!guidance) {
    return null;
  }

  return (
    <Card sx={{ mb: 2 }}>
      <CardHeader
        title={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {getPolicyTypeIcon(guidance.policy_type)}
            <Typography variant="h6">
              Kubernetes {guidance.version} 안내
            </Typography>
            <Chip
              label={guidance.policy_type}
              color={getPolicyTypeColor(guidance.policy_type)}
              size="small"
            />
          </Box>
        }
        action={
          onClose && (
            <Button size="small" onClick={onClose}>
              닫기
            </Button>
          )
        }
      />
      <CardContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {/* 제목 및 설명 */}
          <Box>
            <Typography variant="h6" gutterBottom>
              {guidance.title}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {guidance.description}
            </Typography>
          </Box>

          {/* 주요 기능 */}
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon color="success" />
                <Typography variant="subtitle2" fontWeight="bold">
                  주요 기능
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                {guidance.key_features.map((item: string, index: number) => (
                  <ListItem key={index} sx={{ py: 0 }}>
                    <ListItemText primary={`• ${item}`} />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>

          {/* 제한사항 */}
          {guidance.limitations.length > 0 && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <WarningIcon color="warning" />
                  <Typography variant="subtitle2" fontWeight="bold">
                    제한사항
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <List dense>
                  {guidance.limitations.map((item: string, index: number) => (
                    <ListItem key={index} sx={{ py: 0 }}>
                      <ListItemText 
                        primary={`• ${item}`}
                        primaryTypographyProps={{ color: 'warning.main' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          )}

          {/* 권장사항 */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <InfoIcon color="info" />
                <Typography variant="subtitle2" fontWeight="bold">
                  권장사항
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                {guidance.recommendations.map((item: string, index: number) => (
                  <ListItem key={index} sx={{ py: 0 }}>
                    <ListItemText primary={`• ${item}`} />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>

          {/* 마이그레이션 단계 */}
          {guidance.migration_steps.length > 0 && guidance.migration_steps[0] !== "이미 최신 버전이므로 마이그레이션 불필요" && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <WarningIcon color="error" />
                  <Typography variant="subtitle2" fontWeight="bold">
                    마이그레이션 단계
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <List dense>
                  {guidance.migration_steps.map((item: string, index: number) => (
                    <ListItem key={index} sx={{ py: 0 }}>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          )}

          {/* 예시 */}
          {guidance.examples.length > 0 && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <InfoIcon />
                  <Typography variant="subtitle2" fontWeight="bold">
                    예시
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Paper
                  sx={{
                    p: 2,
                    backgroundColor: 'grey.100',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                    whiteSpace: 'pre-wrap'
                  }}
                >
                  {guidance.examples.join('\n')}
                </Paper>
              </AccordionDetails>
            </Accordion>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default VersionGuidance; 