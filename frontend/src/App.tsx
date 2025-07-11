import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Box,
  TextField,
  Button,
  Paper,
  Grid,
  LinearProgress,
  Alert,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tabs,
  Tab,
  Divider,
} from '@mui/material';
import { checklistApi, ragApi, VersionInfo } from './api';
import { ChecklistResponse, CheckItem, UserContext } from './types';
import ChecklistTree from './components/ChecklistTree';
import VersionGuidance from './components/VersionGuidance';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

function App() {
  const [userInput, setUserInput] = useState('');
  const [errorLogs, setErrorLogs] = useState('');
  const [userContext, setUserContext] = useState<UserContext>({});
  const [checklist, setChecklist] = useState<ChecklistResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Version and RAG state
  const [selectedVersion, setSelectedVersion] = useState('1.24');
  const [availableVersions, setAvailableVersions] = useState<string[]>(['1.20', '1.21', '1.22', '1.23', '1.24', '1.25', '1.26', '1.27', '1.28']);
  const [versionLoading, setVersionLoading] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  
  // RAG state
  const [yamlContent, setYamlContent] = useState('');
  const [ragResult, setRagResult] = useState<any>(null);
  const [ragLoading, setRagLoading] = useState(false);
  
  // Version guidance state
  const [showVersionGuidance, setShowVersionGuidance] = useState(false);

  // Load available versions on component mount
  useEffect(() => {
    loadAvailableVersions();
  }, []);

  const loadAvailableVersions = async () => {
    setVersionLoading(true);
    setError(null);
    try {
      const versionInfo: VersionInfo = await ragApi.getAvailableVersions();
      if (versionInfo.available_versions && versionInfo.available_versions.length > 0) {
        setAvailableVersions(versionInfo.available_versions);
        setSelectedVersion(versionInfo.available_versions[0]);
      } else {
        // Fallback to default versions
        const defaultVersions = ['1.20', '1.21', '1.22', '1.23', '1.24', '1.25', '1.26', '1.27', '1.28'];
        setAvailableVersions(defaultVersions);
        setSelectedVersion('1.24');
      }
    } catch (err) {
      console.error('Error loading versions:', err);
      // Keep default versions on error
      const defaultVersions = ['1.20', '1.21', '1.22', '1.23', '1.24', '1.25', '1.26', '1.27', '1.28'];
      setAvailableVersions(defaultVersions);
      setSelectedVersion('1.24');
    } finally {
      setVersionLoading(false);
    }
  };

  const handleCreateChecklist = async () => {
    if (!userInput.trim()) {
      setError('문제 설명을 입력해주세요.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await checklistApi.createChecklist({
        user_input: userInput,
        error_logs: errorLogs || undefined,
        user_context: Object.keys(userContext).length > 0 ? userContext : undefined,
      });
      
      setChecklist(response);
    } catch (err) {
      setError('체크리스트 생성 중 오류가 발생했습니다.');
      console.error('Error creating checklist:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleItemCheck = async (itemId: string, isChecked: boolean) => {
    if (!checklist) return;

    try {
      const response = await checklistApi.updateProgress({
        checklist: checklist.checklist,
        item_id: itemId,
        is_checked: isChecked,
      });
      
      setChecklist(response);
    } catch (err) {
      setError('진행 상황 업데이트 중 오류가 발생했습니다.');
      console.error('Error updating progress:', err);
    }
  };

  const handleItemNotes = async (itemId: string, notes: string) => {
    if (!checklist) return;

    try {
      const response = await checklistApi.updateProgress({
        checklist: checklist.checklist,
        item_id: itemId,
        is_checked: false, // 노트만 업데이트
        user_notes: notes,
      });
      
      setChecklist(response);
    } catch (err) {
      setError('노트 저장 중 오류가 발생했습니다.');
      console.error('Error saving notes:', err);
    }
  };

  const handleAnalyzePod = async () => {
    if (!yamlContent.trim()) {
      setError('YAML 내용을 입력해주세요.');
      return;
    }

    setRagLoading(true);
    setError(null);

    try {
      const result = await ragApi.analyzePod({
        yaml_content: yamlContent,
        kubernetes_version: selectedVersion,
        target_policy_level: 'restricted',
        use_llm: true,
      });
      
      setRagResult(result);
    } catch (err) {
      setError('Pod 분석 중 오류가 발생했습니다.');
      console.error('Error analyzing pod:', err);
    } finally {
      setRagLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h3" component="h1" gutterBottom align="center">
        Kubernetes 보안 분석 시스템
      </Typography>
      
      <Typography variant="subtitle1" align="center" color="text.secondary" gutterBottom>
        버전별 RAG 기반 Kubernetes 보안 가이드
      </Typography>

      {/* Version Selection */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <FormControl fullWidth disabled={versionLoading}>
              <InputLabel>Kubernetes 버전</InputLabel>
              <Select
                value={selectedVersion}
                label="Kubernetes 버전"
                onChange={(e) => setSelectedVersion(e.target.value)}
              >
                {availableVersions.map((version) => (
                  <MenuItem key={version} value={version}>
                    {version}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              사용 가능한 버전: {availableVersions.length}개
            </Typography>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button
                variant="outlined"
                onClick={loadAvailableVersions}
                disabled={versionLoading}
                startIcon={versionLoading ? <CircularProgress size={16} /> : null}
              >
                {versionLoading ? '로딩 중...' : '버전 새로고침'}
              </Button>
              <Button
                variant="outlined"
                color="info"
                onClick={() => setShowVersionGuidance(!showVersionGuidance)}
              >
                {showVersionGuidance ? '안내문 숨기기' : '버전 안내문 보기'}
              </Button>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              현재 선택: {selectedVersion}
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* Version Guidance */}
      {showVersionGuidance && (
        <Paper sx={{ p: 2, mb: 3 }}>
          <VersionGuidance 
            version={selectedVersion} 
            onClose={() => setShowVersionGuidance(false)}
          />
        </Paper>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="기능 선택">
          <Tab label="체크리스트" />
          <Tab label="Pod 보안 분석" />
        </Tabs>
      </Box>

      {/* Checklist Tab */}
      <TabPanel value={tabValue} index={0}>
        {!checklist ? (
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              문제 상황을 설명해주세요
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={4}
                  label="문제 설명"
                  placeholder="예: Pod가 계속 재시작되고 있어요. Connection refused 에러가 발생합니다."
                  value={userInput}
                  onChange={(e) => setUserInput(e.target.value)}
                  disabled={loading}
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  label="에러 로그 (선택사항)"
                  placeholder="에러 로그를 여기에 붙여넣으세요..."
                  value={errorLogs}
                  onChange={(e) => setErrorLogs(e.target.value)}
                  disabled={loading}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="클라우드 플랫폼"
                  placeholder="예: AWS, GCP, Azure"
                  value={userContext.cloud_platform || ''}
                  onChange={(e) => setUserContext(prev => ({ ...prev, cloud_platform: e.target.value }))}
                  disabled={loading}
                />
              </Grid>
              
              <Grid item xs={12}>
                <Button
                  variant="contained"
                  size="large"
                  onClick={handleCreateChecklist}
                  disabled={loading || !userInput.trim()}
                  sx={{ mt: 2 }}
                >
                  {loading ? <CircularProgress size={24} /> : '체크리스트 생성'}
                </Button>
              </Grid>
            </Grid>
          </Paper>
        ) : (
          <Box>
            {/* 진행 상황 표시 */}
            <Paper sx={{ p: 2, mb: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                <Typography variant="h6">
                  진행 상황
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {checklist.progress_summary.checked_items} / {checklist.progress_summary.total_items} 완료
                </Typography>
              </Box>
              
              <LinearProgress
                variant="determinate"
                value={checklist.progress_summary.progress_percentage}
                sx={{ mb: 1 }}
              />
              
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <Typography variant="body2">
                  진행률: {checklist.progress_summary.progress_percentage.toFixed(1)}%
                </Typography>
                <Typography variant="body2" color="error">
                  Critical 항목: {checklist.progress_summary.critical_items}개
                </Typography>
              </Box>
            </Paper>

            {/* 체크리스트 트리 */}
            <Paper sx={{ p: 3 }}>
              <ChecklistTree
                items={checklist.checklist.root.children}
                onItemCheck={handleItemCheck}
                onItemNotes={handleItemNotes}
              />
            </Paper>
          </Box>
        )}
      </TabPanel>

      {/* Pod Security Analysis Tab */}
      <TabPanel value={tabValue} index={1}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Pod 보안 설정 분석 (버전: {selectedVersion})
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={10}
                label="Pod YAML 설정"
                placeholder="apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
..."
                value={yamlContent}
                onChange={(e) => setYamlContent(e.target.value)}
                disabled={ragLoading}
              />
            </Grid>
            
            <Grid item xs={12}>
              <Button
                variant="contained"
                size="large"
                onClick={handleAnalyzePod}
                disabled={ragLoading || !yamlContent.trim()}
                sx={{ mt: 2 }}
              >
                {ragLoading ? <CircularProgress size={24} /> : '보안 분석 실행'}
              </Button>
            </Grid>
          </Grid>

          {ragResult && (
            <Box sx={{ mt: 4 }}>
              <Divider sx={{ my: 2 }} />
              <Typography variant="h6" gutterBottom>
                분석 결과
              </Typography>
              
              {/* Version Note */}
              {ragResult.version_note && (
                <Paper sx={{ p: 2, mb: 2, bgcolor: 'info.light' }}>
                  <Typography variant="subtitle1" gutterBottom>
                    📋 버전 안내
                  </Typography>
                  <Typography variant="body1">
                    {ragResult.version_note}
                  </Typography>
                </Paper>
              )}

              {/* LLM Korean Advice */}
              {ragResult.llm_korean_advice && (
                <Paper sx={{ p: 2, mb: 2, bgcolor: 'primary.light', color: 'white' }}>
                  <Typography variant="subtitle1" gutterBottom>
                    🤖 AI 보안 조언
                  </Typography>
                  <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                    {ragResult.llm_korean_advice}
                  </Typography>
                </Paper>
              )}

              {/* Fixed YAML */}
              {ragResult.fixed_yaml && (
                <Paper sx={{ p: 2, mb: 2 }}>
                  <Typography variant="subtitle1" gutterBottom>
                    🔧 수정된 YAML
                  </Typography>
                  <TextField
                    fullWidth
                    multiline
                    rows={8}
                    value={ragResult.fixed_yaml}
                    InputProps={{ readOnly: true }}
                    sx={{ fontFamily: 'monospace' }}
                  />
                </Paper>
              )}

              {/* Analysis Details */}
              {ragResult.analysis && (
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" gutterBottom>
                    📊 분석 상세
                  </Typography>
                  <pre style={{ overflow: 'auto', maxHeight: '400px' }}>
                    {JSON.stringify(ragResult.analysis, null, 2)}
                  </pre>
                </Paper>
              )}
            </Box>
          )}
        </Paper>
      </TabPanel>
    </Container>
  );
}

export default App; 