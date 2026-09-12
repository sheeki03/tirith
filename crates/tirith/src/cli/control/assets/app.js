'use strict';
(() => {
  const content = document.querySelector('#content');
  const notice = document.querySelector('#notice');
  const dialog = document.querySelector('#operation-dialog');
  const operationContent = document.querySelector('#operation-content');
  const operationActions = document.querySelector('#operation-actions');
  const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  history.replaceState(null, '', location.pathname);
  let csrf = '', currentPage = 'overview', generation = 0, dialogGeneration = 0, activeOperation = null, pollTimer = null, pendingPlan = null, pendingLifecycle = null, planRequest = null, lifecycleRequest = null;
  const pages = {
    overview: ['Overview', 'Protection evidence from this computer.'],
    activity: ['Activity', 'Recorded checks and interruptions, with the limits of the available history.'],
    protection: ['Protection', 'Choose your personal baseline and inspect the policy that actually takes effect.'],
    exceptions: ['Exceptions', 'Specific, scoped permissions with expiry and an explanation.'],
    integrations: ['Integrations', 'Configuration, loaded versions, and observed behavior are separate facts.'],
    settings: ['Settings', 'Installation, freshness, compatibility, and local service controls.']
  };
  function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
  function button(text, fn, className = '') { const node = element('button', text, className); node.type = 'button'; node.addEventListener('click', async () => { node.disabled = true; try { await fn(); } catch (error) { showError(error); } finally { node.disabled = false; } }); return node; }
  function badge(text, warning = false) { return element('span', String(text).replace(/[_-]/g, ' '), `badge${warning ? ' warning' : ''}`); }
  function panel(title) { const node = element('section', undefined, 'panel'); if (title) node.append(element('h2', title)); return node; }
  function paragraph(text, className) { return element('p', text, className); }
  function rawDetails(title, value) { const node = element('details'); node.append(element('summary', title), element('pre', JSON.stringify(value, null, 2))); return node; }
  function row(title, detail, status, actions = []) { const node = element('div', undefined, 'row'); const copy = element('div'); copy.append(element('strong', title), element('small', detail)); node.append(copy); if (status) node.append(badge(status)); if (actions.length) { const group = element('div', undefined, 'actions'); group.append(...actions); node.append(group); } return node; }
  function showError(error) { notice.textContent = error.message || String(error); notice.hidden = false; }
  async function api(path, body) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 35000);
    try {
      const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
        headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'X-Tirith-CSRF': csrf }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const value = await response.json();
      if (!response.ok) { if (response.status === 401) document.querySelector('#session-state').textContent = 'Session expired — reopen with tirith dashboard'; throw new Error(value.error || 'Local request failed'); }
      if (value.diagnostics?.length) showError(new Error(value.diagnostics.join('\n')));
      return value;
    } catch (error) { if (error.name === 'AbortError') throw new Error('The response timed out. A submitted operation may still be running; inspect its stored ID before retrying.'); throw error; }
    finally { clearTimeout(timer); }
  }
  async function overview() {
    const [state, policy, fresh] = await Promise.all([api('/api/state'), api('/api/policy'), api('/api/freshness')]);
    const evidence = state.shell.protection_evidence;
    const hero = panel(); hero.classList.add('hero'); hero.append(badge(evidence.verified_blocking ? 'Observed evidence' : 'Verification needed', !evidence.verified_blocking),
      element('h2', evidence.verified_blocking ? 'Blocking observed on this surface' : state.shell.hook_configured ? 'Configured. Verify in your shell.' : 'Check your integration.'),
      paragraph(evidence.invalidation_reason || `Evidence source: ${evidence.source}`),
      button('Inspect integrations', () => navigate('integrations'), 'primary'));
    const surfaces = panel('Your protection context');
    surfaces.append(row('Terminal integration', 'A configured hook is not proof that a command was intercepted.', evidence.state),
      row('Personal baseline', 'Repository, organization, remote, or incident restrictions may constrain your selection.', policy.resolution?.requested_profile?.name || policy.policy?.protection_profile?.name || 'Custom / default'),
      row('Threat intelligence', fresh.error || 'Signature verification and source freshness are reported independently.', fresh.status),
      row('Project', state.project, 'Service scope'));
    if (state.audit_recording) surfaces.append(row('Audit recording', state.audit_recording.detail, state.audit_recording.state,
      [button('Inspect activity coverage', () => navigate('activity'))]));
    return [hero, surfaces, projectReviewPanel(), npmArtifactPanel(), rawDetails('Inspect effective policy evidence', policy)];
  }
  function npmArtifactPanel() {
    const section = panel('Inspect a local npm package');
    const current = field('npm tarball in this project', 'text', '', 'artifacts/package.tgz');
    const previous = field('Previous npm tarball (for comparison)', 'text', '', 'artifacts/package-previous.tgz');
    for (const input of [current.input, previous.input]) input.maxLength = 512;
    section.append(paragraph('Inspect the exact bytes of a project-relative .tgz or .tar.gz file, up to 32 MiB compressed. Static observations include script, code and native-file evidence. Nothing is installed or executed, and registry provenance is unavailable offline.'), current.label, previous.label,
      button('Inspect npm tarball', async () => { const request = {action:'inspect', path:current.input.value.trim()}; await requestDialog(() => api('/api/artifacts/npm', request), value => showNpmReport(value, request)); }, 'primary'),
      button('Compare npm tarballs', async () => { const request = {action:'compare', old_path:previous.input.value.trim(), new_path:current.input.value.trim()}; await requestDialog(() => api('/api/artifacts/npm', request), value => showNpmReport(value, request)); }));
    return section;
  }
  function showNpmReport(value, request) {
    const comparison = value.kind === 'npm_comparison';
    showDialog(comparison ? 'npm release comparison' : 'npm artifact inspection', value);
    operationContent.prepend(paragraph('This report describes captured archive bytes. A later change to either path requires another inspection. Absence of a finding does not prove package behavior or grant permission to install.', 'notice'));
    if (comparison) {
      operationContent.append(row('Previous archive SHA-256', value.old_artifact.sha256 || 'Unavailable', value.old_artifact.filename),
        row('Selected archive SHA-256', value.new_artifact.sha256 || 'Unavailable', value.new_artifact.filename),
        paragraph(`${value.total_deltas} observed changes · ${value.omitted_deltas} omitted from display · ${value.capability_comparison_available ? 'Capability observations comparable' : 'Capability comparison unavailable'}.`));
      for (const delta of value.deltas || []) operationContent.append(rawDetails(delta.kind, delta));
      for (const note of value.notes || []) operationContent.append(paragraph(typeof note === 'string' ? note : JSON.stringify(note), 'notice'));
    } else {
      for (const artifact of value.artifacts || []) {
        const detail = panel(artifact.artifact.filename); detail.append(badge(artifact.status), row('Archive SHA-256', artifact.artifact.sha256 || 'Unavailable', 'Captured bytes'),
          paragraph(`Archive: ${artifact.coverage.archive_complete ? 'fully read within supported format' : 'incomplete or refused'} · Metadata: ${artifact.coverage.metadata_complete ? 'inspected' : 'incomplete'} · Code: ${artifact.coverage.static_analysis_complete ? 'selected static checks complete' : 'partial'}.`));
        for (const signal of artifact.signals || []) detail.append(row(signal.kind, `${signal.member}: ${signal.evidence}`, signal.level));
        for (const issue of artifact.coverage.issues || []) detail.append(paragraph(`${issue.kind}: ${issue.detail}`, 'notice'));
        detail.append(paragraph(`${artifact.omitted_files} file details and ${artifact.omitted_signals} observations omitted from display.`, 'muted'));
        operationContent.append(detail);
      }
    }
    operationActions.append(button('Refresh and download npm report', async () => download('tirith-npm-report.json', await api('/api/artifacts/npm', request))));
  }
  function projectReviewPanel() {
    const section = panel('Review this project');
    const label = element('label', 'Project-relative files (optional)'); const paths = element('textarea'); paths.rows = 3; paths.maxLength = 8192; paths.setAttribute('aria-label', 'Project-relative files (optional)'); label.append(paths);
    section.append(paragraph('Explicitly inspect dependency declarations, known hook files, AI instructions and MCP configuration in this service’s project. No package manager, hook or server is started. Leave the list empty to review known surfaces; nested workspaces and unselected files remain uninspected.'), label,
      button('Inspect selected project files', () => requestDialog(() => api('/api/project/review', {paths:paths.value.split('\n').map(path => path.trim()).filter(Boolean)}), showProjectReview), 'primary'));
    return section;
  }
  function showProjectReview(value) {
    showDialog('Project review', value);
    operationContent.prepend(paragraph(value.notice, 'notice'), paragraph(`${value.coverage.selected_files} selected files · ${value.coverage.inspected_bytes} inspected bytes · ${value.changed_files} identities changed since capture.`));
    if (value.presentation_incomplete) operationContent.append(paragraph('Some report details exceed the display limit. Select fewer files to inspect their evidence.', 'notice'));
    for (const file of value.files || []) {
      const item = panel(file.path); item.append(badge(file.status), paragraph((file.gaps || []).join(' · '), 'muted'));
      for (const finding of file.findings || []) item.append(paragraph(`${finding.rule_id}: ${finding.description}`));
      if (file.dependency_count) item.append(paragraph(`${file.dependencies?.length || 0} assessed among ${file.dependency_count} declared dependencies. Artifact code was not inspected.`));
      operationContent.append(item);
    }
    operationActions.append(button('Recheck retained file identities', () => requestDialog(() => api('/api/project/revalidate', {report_id:value.report_id}), showProjectReview)));
  }
  async function activity() {
    const wrapper = element('div'); const tools = element('form', undefined, 'toolbar');
    wrapper.append(await activitySummary());
    const action = select('Action', [['', 'All actions'], ['allow', 'Allow'], ['warn', 'Warn'], ['warn_ack', 'Acknowledgement'], ['block', 'Block']]);
    const rule = field('Rule ID', 'text', '', 'Optional exact rule ID');
    const since = field('Since', 'datetime-local'); const result = element('div');
    tools.append(action.label, rule.label, since.label); const submit = element('button', 'Filter', 'primary'); submit.type = 'submit'; tools.append(submit); wrapper.append(tools, result);
    let cursor = null; let activeFilter = {}, rows = new Map(); let querySequence = 0;
    async function load(reset) {
      const query = ++querySequence;
      if (reset) { cursor = null; rows = new Map(); activeFilter = { action: action.input.value || null, rule: rule.input.value.trim() || null, since: since.input.value ? new Date(since.input.value).toISOString() : null, until: null }; }
      const data = await api('/api/history', { cursor, filter: activeFilter, limit: 100 });
      if (query !== querySequence) return;
      if (data.availability === 'refresh_required') { rows.clear(); cursor = null; result.replaceChildren(paragraph('The history source changed or this cursor expired. Refresh the filter to start a new view.', 'notice')); return; }
      const annotations = new Map((data.annotations?.entries || []).map(entry => [entry.event_id, entry]));
      for (const event of [...(data.events || [])].reverse()) { event.annotation = annotations.get(event.record?.event_id); rows.set(event.record_id, event); }
      while (rows.size > 1000) rows.delete([...rows.keys()].pop());
      cursor = data.next_cursor; result.replaceChildren();
      const coverage = panel('Collection coverage'); coverage.append(badge(data.availability), paragraph(`${[...rows.values()].filter(event => event.semantics === 'recorded_check').length} recorded checks among ${rows.size} loaded records (at most 1,000 retained in the browser). These counts do not establish execution or attacks prevented.`),
        paragraph(data.detail || (data.earlier_history_uninspected ? 'Older history has not been inspected in this bounded view.' : 'Coverage is limited to the inspected records.')),
        paragraph(`Malformed records: ${data.malformed_lines || 0}. Oversized records: ${data.oversized_lines || 0}. Unfinished tail: ${data.incomplete_tail ? 'yes' : 'no'}. Audit integrity: ${data.integrity || 'not verified by this reader'}.`, 'muted'));
      if (data.audit_recording) coverage.append(paragraph(data.audit_recording.detail, data.audit_recording.state === 'failure_observed' ? 'notice' : 'muted'), rawDetails('Audit writer observations', data.audit_recording));
      result.append(coverage);
      if (!rows.size) result.append(paragraph('No recorded activity is available for this selection.', 'empty'));
      const list = panel('Recorded activity'); const counts = new Map();
      for (const event of rows.values()) {
        const record = event.record || event.event || event;
        if (event.semantics === 'recorded_check') for (const ruleId of new Set(record.rule_ids || [])) counts.set(ruleId, (counts.get(ruleId) || 0) + 1);
        const item = element('div', undefined, 'row'); const copy = element('div'); copy.append(element('strong', record.timestamp || 'Timestamp unavailable'), element('code', record.command_redacted || record.input || record.command || record.command_preview || 'Command text not retained'), rawDetails('Inspect recorded evidence', record));
        if (event.annotation?.availability === 'available') copy.append(paragraph(`Your recorded expectation: ${event.annotation.expectation}. This label does not establish safety or execution.`, 'muted'));
        else if (event.annotation?.availability === 'unavailable') copy.append(paragraph('The saved expectation could not be read or did not match this incident.', 'muted'));
        item.append(copy, badge(record.action || 'Unknown action'));
        if (event.semantics === 'recorded_check' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(record.event_id || '')) item.append(button('Record expectation', () => {
          showDialog('Label what you intended', {detail:'This annotation does not prove the operation was safe or executed. It cannot create an exception or approve future commands.'});
          const expectation = select('Was this operation intended?', [['expected','Expected operation'],['unexpected','Unexpected operation'],['unsure','Unsure']]);
          if (event.annotation?.availability === 'available') expectation.input.value = event.annotation.expectation;
          operationContent.prepend(expectation.label);
          operationActions.append(button('Review expectation label', () => plan({kind:'feedback', change:{event_id:record.event_id, expectation:expectation.input.value}}), 'primary'));
        }));
        list.append(item);
      }
      if (rows.size) { const summary = panel('Rules in these loaded records'); summary.append(paragraph([...counts].sort((a,b) => b[1]-a[1]).map(([name, count]) => `${name}: ${count}`).join(' · ') || 'No rule IDs in these records.')); result.append(summary, list); }
      result.append(button('Refresh recent activity', () => load(true)));
      if (cursor && rows.size < 1000) result.append(button('Load older bounded page', () => load(false)));
      else if (cursor) result.append(paragraph('The browser has reached its 1,000-record limit. Narrow the filter to inspect other records.', 'muted'));
    }
    tools.addEventListener('submit', event => { event.preventDefault(); load(true).catch(showError); }); await load(true); return [wrapper];
  }
  async function activitySummary() {
    const data = await api('/api/activity/summary'); const summary = panel('Recent checks and recurring interruptions');
    summary.append(badge(data.availability), paragraph(`${data.window_start} to ${data.window_end} · UTC calendar days · ${data.counts.recorded_checks} collected checks`),
      paragraph(`${data.counts.blocked_checks} blocked · ${data.counts.warning_checks} warnings · ${data.counts.acknowledgement_required_checks} acknowledgement requests · ${data.counts.bypass_honored_checks} recorded honored bypasses`),
      paragraph(`This bounded collector has ${data.earlier_history_uninspected ? 'not inspected earlier history' : 'inspected the available source from its beginning'}. ${data.more_available ? 'More records remain to collect; refresh to continue.' : ''} Counts do not establish execution. The collector does not verify the audit chain.`, 'muted'));
    if (['absent','unreadable','disabled','refresh_required','corrupt'].includes(data.availability)) summary.append(paragraph('Collection is unavailable or incomplete. A count of zero in this collector does not prove there were no checks.', 'notice'));
    if (!data.rules.length) summary.append(paragraph('No rule-bearing checks in the collected window.', 'empty'));
    for (const rule of data.rules.slice(0, 10)) {
      const entry = element('details'); entry.append(element('summary', `${rule.rule_id}: ${rule.interruptions} interruptions in ${rule.recorded_checks} checks`));
      for (const example of rule.examples) entry.append(paragraph(`${example.timestamp} · ${example.action}`), element('code', example.command_preview));
      summary.append(entry);
    }
    summary.append(rawDetails('Inspect aggregate coverage', data)); return summary;
  }
  async function protection() {
    const effective = await api('/api/policy'); const intro = panel('Personal protection profile');
    intro.append(paragraph('Profiles change owned personal settings. A preview shows custom overrides and constraints before anything is applied.'));
    const choices = element('div', undefined, 'grid');
    for (const [name, description] of [['comfortable', 'Fewer interruptions with warnings for suspicious operations.'], ['balanced', 'Selected approval requirements for higher-risk operations.'], ['strict', 'Stronger enforcement and conservative handling of incomplete checks.']]) {
      const choice = element('section', undefined, 'profile'); choice.append(element('h3', name[0].toUpperCase() + name.slice(1)), paragraph(description), button('Compare and review', () => previewProfile(name), 'primary')); choices.append(choice);
    }
    intro.append(choices, button('Preview reset of owned profile settings', () => previewProfile('reset'), 'secondary'));
    const details = panel('Effective settings and constraints'); details.append(paragraph('This is the resolver’s effective policy. A saved preference may be overridden by a stronger authority.'), rawDetails('Inspect settings, source provenance, and neutralized values', effective));
    const tuning = panel('Review recurring interruptions');
    tuning.append(paragraph('Inspect bounded recent check counts, recorded expectations, and redacted examples before choosing a change. Repeated warnings, allowed decisions and user labels do not prove a relaxation is safe.'),
      button('Review recent friction', () => requestDialog(() => api('/api/policy/tuning'), value => {
        showDialog('Recent friction review', value);
        operationContent.prepend(paragraph(value.notice, 'notice'), paragraph(`${value.records_analyzed} recorded checks inspected. Older history uninspected: ${value.coverage.earlier_history_uninspected ? 'yes' : 'no'}.`), paragraph(value.next_action));
      })));
    return [intro, tuning, rolloutPanel(), advancedSettings(effective), details];
  }
  function rolloutPanel() {
    const section = panel('Review profile impact'); const form = element('form');
    const profile = select('Candidate profile', [['comfortable','Comfortable'],['balanced','Balanced'],['strict','Strict']]); profile.input.value = 'balanced';
    const shell = select('Workflow shell', [['posix','Bash / Zsh / POSIX'],['fish','Fish'],['powershell','PowerShell']]);
    const commandsLabel = element('label','Representative commands, one per line'); const commands = element('textarea'); commands.rows = 5; commands.required = true; commands.maxLength = 12000; commandsLabel.append(commands);
    const interactive = field('Model interactive operation', 'checkbox'); interactive.input.checked = true;
    const submit = element('button','Prepare impact review','primary'); submit.type='submit';
    form.append(profile.label, shell.label, commandsLabel, interactive.label, submit);
    form.addEventListener('submit', event => { event.preventDefault(); plan({kind:'policy_rollout', change:{profile:profile.input.value, commands:commands.value.split('\n').filter(value => value.trim()), shell:shell.input.value, interactive:interactive.input.checked}}).catch(showError); });
    section.append(paragraph('Compare explicit workflows against one captured policy context before changing your personal profile. Commands are analyzed without execution. Missing runtime evidence remains unavailable; this review cannot establish fleet adoption or approve an operation.'), form); return section;
  }
  function advancedSettings(effective) {
    const section = panel('Advanced personal settings'); const form = element('form');
    const setting = select('Setting', [['strict_warn', 'Require acknowledgement for warnings'], ['allow_bypass_env', 'Permit explicit interactive bypass'], ['allow_bypass_env_noninteractive', 'Permit explicit noninteractive bypass'], ['scan_require_complete', 'Require complete scan coverage'], ['env_guard_enabled', 'Environment guard'], ['context_guard_enabled', 'Context guard'], ['exec_guard_enabled', 'Executable guard'], ['hooks_guard_enabled', 'Repository hooks guard'], ['baseline_enabled', 'Baseline checks'], ['mcp_redact_injection', 'Redact injection in MCP output'], ['fail_mode', 'Behavior on internal check failure'], ['paranoia', 'Heuristic sensitivity'], ['rule_severity', 'Specific rule severity']]);
    const value = select('Personal value', []); const rule = field('Rule to customize', 'text', '', 'Exact rule ID'); const current = paragraph('', 'muted');
    function choices() {
      value.input.replaceChildren();
      const options = setting.input.value === 'fail_mode' ? [['open', 'Open'], ['closed', 'Closed']] : setting.input.value === 'paranoia' ? [1,2,3,4].map(n => [String(n), String(n)]) : setting.input.value === 'rule_severity' ? [['LOW','Low'],['MEDIUM','Medium'],['HIGH','High'],['CRITICAL','Critical']] : [['true','Enabled'],['false','Disabled']];
      for (const [key, title] of [['reset', 'Remove personal override'], ...options]) { const option = element('option', title); option.value = key; value.input.append(option); }
      rule.label.hidden = setting.input.value !== 'rule_severity'; rule.input.required = !rule.label.hidden;
      const path = setting.input.value === 'scan_require_complete' ? ['scan','require_complete'] : [setting.input.value];
      const effectiveValue = path.reduce((part, key) => part?.[key], effective.policy);
      current.textContent = `Current effective value: ${effectiveValue === undefined ? 'inspect the rule in effective settings below' : JSON.stringify(effectiveValue)}. Stronger policy sources may override your personal choice.`;
    }
    setting.input.addEventListener('change', choices); choices();
    const submit = element('button','Compare personal change','primary'); submit.type='submit';
    form.append(setting.label, value.label, rule.label, current, submit);
    form.addEventListener('submit', event => { event.preventDefault(); const selected = value.input.value;
      const change = {setting:setting.input.value, value:selected === 'reset' ? null : selected === 'true' ? true : selected === 'false' ? false : setting.input.value === 'paranoia' ? Number(selected) : selected};
      if (setting.input.value === 'rule_severity') change.rule = rule.input.value.trim();
      requestDialog(() => api('/api/settings/preview', change), preview => { showDialog('Review personal setting', preview); operationActions.append(button('Create change plan', () => plan({kind:'personal_setting',change}), 'primary')); }).catch(showError);
    });
    section.append(paragraph('These changes apply to your personal policy. Profile changes and resets preserve explicit overrides. Removal restores the value inherited from other policy sources.'), form); return section;
  }
  async function previewProfile(profile) {
    return requestDialog(() => api('/api/profile/preview', {profile}), value => {
      showDialog('Review personal profile', value);
      operationActions.append(button('Create change plan', () => plan({kind:'profile', profile}), 'primary'));
    });
  }
  function field(title, type = 'text', value = '', placeholder = '') { const label = element('label', title); const input = element('input'); input.type = type; input.value = value; input.placeholder = placeholder; if (type === 'checkbox') label.replaceChildren(input, document.createTextNode(title)); else label.append(input); return { label, input }; }
  function select(title, options) { const label = element('label', title); const input = element('select'); input.setAttribute('aria-label', title); for (const [value, text] of options) { const option = element('option', text); option.value = value; input.append(option); } label.append(input); return { label, input }; }
  async function exceptions() {
    const data = await api('/api/exceptions'); const wrapper = element('div'); const list = panel('Recorded exceptions');
    const search = field('Search exceptions', 'search'); list.append(search.label); const rows = element('div'); list.append(rows);
    function render() {
      rows.replaceChildren(); const grants = (data.grants || []).filter(grant => JSON.stringify(grant).toLowerCase().includes(search.input.value.toLowerCase()));
      if (!grants.length) rows.append(paragraph('No exceptions match this view.', 'empty'));
      for (const grant of grants) {
        const node = element('div', undefined, 'row'); const copy = element('div'); copy.append(element('strong', grant.pattern || 'Unusable grant'), element('small', `${grant.scope} · ${grant.rule_id || 'All rules'} · ${grant.expires_at || 'No expiry recorded'}`), paragraph(grant.state_reason || '', 'muted'), rawDetails('Inspect exception and scope', grant));
        const actions = element('div', undefined, 'actions');
        if (grant.id) { actions.append(button('Revoke', () => plan({ kind: 'trust_revoke', grant_id: grant.id })), button('Change expiry', () => expiryDialog(grant))); }
        if (grant.id && ['user', 'project'].includes(grant.scope)) actions.append(button('Explain trust eligibility', () => requestDialog(() => api('/api/exceptions/explain', {target:grant.id, scope:grant.scope}), value => showDialog('Permission explanation', value))));
        copy.append(actions); node.append(copy, badge(grant.state || 'Unknown')); rows.append(node);
      }
    }
    search.input.addEventListener('input', render); render();
    const add = panel('Add a scoped exception'); const form = element('form'); const pattern = field('Exact target', 'text', '', 'https://example.org/install.sh'); pattern.input.required = true;
    const rule = field('Rule ID', 'text', '', 'Exact rule ID'); rule.input.required = true;
    const broad = field('Allow a domain or wildcard target', 'checkbox');
    const allRules = field('Apply to all eligible rules', 'checkbox');
    const permanent = field('Keep this exception without an expiry', 'checkbox');
    allRules.input.addEventListener('change', () => { rule.input.required = !allRules.input.checked; rule.input.disabled = allRules.input.checked; });
    const scope = select('Scope', [['project', 'This project'], ['user', 'This user']]); const ttl = field('Expiry', 'text', '7d', 'For example, 7d');
    const reason = field('Reason', 'text'); const submit = element('button', 'Review exception', 'primary'); submit.type = 'submit';
    permanent.input.addEventListener('change', () => { ttl.input.disabled = permanent.input.checked; });
    form.append(pattern.label, rule.label, scope.label, ttl.label, reason.label, broad.label, allRules.label, permanent.label, paragraph('Domain, wildcard, all-rule, and permanent permissions apply only when explicitly selected. Independent hard blocks and project restrictions remain in effect.', 'muted'), submit);
    form.addEventListener('submit', event => { event.preventDefault(); plan({ kind: 'trust_add', pattern: pattern.input.value.trim(), rule: allRules.input.checked ? null : rule.input.value.trim(), scope: scope.input.value, ttl: permanent.input.checked ? null : ttl.input.value.trim(), broad: broad.input.checked, all_rules: allRules.input.checked, permanent: permanent.input.checked, reason: reason.input.value.trim() || null }).catch(showError); });
    add.append(form); wrapper.append(list, add); return [wrapper];
  }
  function expiryDialog(grant) { showDialog('Change exception expiry', { grant_id: grant.id, target: grant.pattern, current_expiry: grant.expires_at }); const ttl = field('New expiry', 'text', '7d'); operationContent.append(ttl.label); operationActions.append(button('Review expiry change', () => plan({ kind: 'trust_expiry', grant_id: grant.id, ttl: ttl.input.value.trim() }), 'primary')); }
  async function integrations() {
    const [state, lifecycle] = await Promise.all([api('/api/integrations'), api('/api/lifecycle')]); const info = state.shell; const surface = panel('Terminal integration');
    surface.append(row('Startup configuration', 'The intended startup file and active process may differ.', info.hook_configured ? 'Configured' : 'Not configured'),
      row('Protection observation', info.protection_evidence.invalidation_reason || info.protection_evidence.source, info.protection_evidence.state),
      row('Loaded integration version', lifecycle.loaded_integration.evidence, lifecycle.loaded_integration.version || 'Unknown'),
      row('Required next action', lifecycle.loaded_integration.next_action, lifecycle.loaded_integration.reload_status));
    const setup = panel('Set up or repair a shell'); const shell = select('Intended shell', [['', 'Choose a shell'], ['bash', 'Bash'], ['zsh', 'Zsh'], ['fish', 'Fish'], ['nushell', 'Nushell'], ['powershell', 'Windows PowerShell 5.1'], ['pwsh', 'PowerShell 7']]);
    const choose = () => { if (!shell.input.value) throw new Error('Choose the shell whose startup configuration you want to change.'); return shell.input.value; };
    setup.append(paragraph('Tirith discovers the personal startup files for the selected shell. Review every destination before applying. Restart that shell after setup, repair, removal, or undo.'), shell.label,
      button('Inspect selected configuration', () => requestDialog(() => api('/api/integrations/inspect', {shell:choose()}), value => showDialog('Shell configuration', value))),
      button('Review setup', () => plan({ kind: 'shell', change: { action: 'install', shell: choose(), force: false } }), 'primary'),
      button('Review repair', () => plan({ kind: 'shell', change: { action: 'install', shell: choose(), force: true } })),
      button('Review removal of owned hook', () => plan({ kind: 'shell', change: { action: 'remove', shell: choose() } })));
    const verify = panel('Verify in the intended shell'); verify.append(paragraph('Open a fresh Bash, Zsh or Fish shell and request the harmless challenge. Run its three exact commands separately in that same shell. The authenticated helper status verifies only that shell; this service cannot reuse inherited markers as blocking evidence. Other shell variants report their actual verification limits.'), element('pre', 'tirith doctor --verify-shell\n_tirith_verification_probe start'), rawDetails('Inspect integration evidence', { state, loaded: lifecycle.loaded_integration }));
    const recommended = panel('Personal setup');
    const recommendedShell = select('Personal setup shell', [['', 'Choose your shell'], ['bash','Bash'], ['zsh','Zsh'], ['fish','Fish']]);
    const recommendedProfile = select('Personal setup profile', [['balanced','Balanced'], ['comfortable','Comfortable'], ['strict','Strict']]);
    recommended.append(paragraph('Review one plan for your personal shell integration and protection profile. Existing manual settings are preserved. A fresh shell and its verification handshake are required after applying. Agent hosts require their separate setup and verification workflows.'), recommendedShell.label, recommendedProfile.label,
      button('Review personal setup', () => {
        if (!recommendedShell.input.value) throw new Error('Choose the shell whose personal startup configuration you intend to change.');
        return plan({kind:'recommended_setup', change:{scope:'user', shell:recommendedShell.input.value, profile:recommendedProfile.input.value, agents:[]}});
      }, 'primary'));
    return [surface, recommended, setup, verify];
  }
  async function settings() {
    const [lifecycle, fresh, jobs, state] = await Promise.all([api('/api/lifecycle'), api('/api/freshness'), api('/api/jobs'), api('/api/state')]); const install = panel('Installation and updates');
    install.append(row('Running binary', lifecycle.installed_binary.evidence, lifecycle.installed_binary.version || 'Unknown'),
      row('Installation channel', lifecycle.upgrade_guidance || 'Inspect your installation before replacing a binary.', lifecycle.install_method),
      row('Available release', lifecycle.release.evidence, lifecycle.release.version || 'Not queried'),
      row('Channel-available version', lifecycle.channel_available.evidence, lifecycle.channel_available.version || 'Not queried'),
      rawDetails('Inspect compatibility and ownership', lifecycle));
    install.append(paragraph('These explicit checks may contact release servers. Review the verified candidate and compatibility result before applying. Package-managed or administrator-owned installations show the required terminal action.'),
      button('Check and review update', () => prepareLifecycle('update'), 'primary'),
      button('Review saved rollback', () => prepareLifecycle('rollback')));
    const sources = panel('Threat intelligence freshness'); sources.append(row('Installed database', fresh.error || 'A signed publication can contain older source data; inspect each dimension.', fresh.status), rawDetails('Inspect publication, source age, and pin adoption', fresh));
    sources.append(button('Check and review database refresh', () => prepareLifecycle('refresh_threat_db')));
    const local = panel('Local service'); local.append(paragraph('Stop accepting changes and close this dashboard service after its active jobs finish. Shell and agent protection continue independently.'), button('Close local service', () => requestDialog(() => api('/api/quiesce', {}), response => { showDialog('Service is draining', response); document.querySelector('#session-state').textContent = 'Service closing — reopen with tirith dashboard'; }), 'secondary'));
    const exportPanel = panel('Export this redacted view'); exportPanel.append(paragraph('Exports refresh the lifecycle and freshness projections under the current privacy policy. Canonical signed files and private operation journals are not included.'), button('Download JSON', async () => { const [currentLifecycle, freshness] = await Promise.all([api('/api/lifecycle'), api('/api/freshness')]); download('tirith-local-status.json', {lifecycle:currentLifecycle, freshness}); }));
    const retention = panel('Audit retention'); retention.append(paragraph('Review a rotation of the active audit history into a private retained segment. Rotation preserves exact archived bytes and starts a checkpointed active segment. Undo requires that no further records have been appended.'), button('Review audit rotation', () => plan({kind:'audit_retention', change:'rotate'})));
    const segment = field('Retained segment ID', 'text', '', 'UUID of the completed rotation operation');
    const erase = field('I understand that deleting this segment permanently removes its retained records', 'checkbox');
    retention.append(segment.label, paragraph('Segment export copies exact retained records to a private local directory; it is not a redacted support report. Deletion keeps a checkpoint and tombstone, leaves the active log intact, and cannot be undone.'),
      button('Review segment export', () => plan({kind:'audit_segment', change:{action:'export', segment_id:segment.input.value.trim()}})), erase.label,
      button('Review permanent segment deletion', () => {
        if (!erase.input.checked) throw new Error('Acknowledge that the retained records cannot be restored before preparing deletion.');
        return plan({kind:'audit_segment', change:{action:'delete', segment_id:segment.input.value.trim(), acknowledge_irreversible:true}});
      }));
    const approval = panel('Optional administrator approval');
    approval.append(row('Native package approval', state.package_approval.detail, state.package_approval.state), paragraph(state.package_approval.next_action), paragraph('Ordinary command checks and shell protection do not require sudo. This dashboard never requests administrator credentials.'));
    const recent = panel('Saved changes and recovery'); recent.append(paragraph('These are saved operation states. Open an operation to reconcile its current status; closing the browser does not cancel submitted work.'));
    if (!jobs.operations.length) recent.append(paragraph('No saved operations in the bounded inventory.', 'empty'));
    for (const operation of jobs.operations) recent.append(row(operation.kind || 'Saved change', operation.operation_id, operation.no_op ? 'unchanged' : operation.state, [button('Open saved operation', () => requestDialog(() => api('/api/operations', {operation_id:operation.operation_id, action:'status'}), stored => { showDialog('Saved operation', stored); displayOperation(stored); }))]));
    recent.append(rawDetails('Inspect inventory coverage', jobs.coverage));
    const lifecycleId = field('Update or refresh operation ID', 'text', '', 'UUID retained from a lifecycle preview');
    recent.append(lifecycleId.label, button('Open saved lifecycle operation', () => requestDialog(() => api('/api/lifecycle/operation', {operation_id:lifecycleId.input.value.trim(), action:'status'}), displayLifecycle)));
    return [install, approval, sources, retention, recent, supportPanel(), local, exportPanel];
  }
  function supportPanel() {
    const support = panel('Prepare a support report');
    const operations = field('Operation IDs', 'text', '', 'Optional UUIDs, separated by commas');
    const incidents = field('Incident event IDs', 'text', '', 'Optional UUIDs from recorded activity');
    const selected = input => input.value.split(',').map(value => value.trim()).filter(Boolean);
    support.append(paragraph('Include only the incidents and saved changes you select. Preview applies the current redaction policy. Older history may be outside the bounded read; no report is uploaded.'), operations.label, incidents.label,
      button('Preview support report', async () => {
        const selection = {operation_ids: selected(operations.input), incident_ids: selected(incidents.input)};
        await requestDialog(() => api('/api/support/preview', selection), value => {
        showDialog('Review support report', value);
        operationContent.prepend(paragraph(value.notice, 'notice'));
        operationActions.append(button('Download with fresh redaction', async () => download('tirith-support.json', await api('/api/support/preview', selection)), 'primary'));
        });
      }));
    return support;
  }
  function download(filename, value) { const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })); const link = element('a'); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  async function prepareLifecycle(action) {
    if (pendingPlan) throw new Error('Inspect or retry the pending settings request before preparing a lifecycle operation.');
    if (pendingLifecycle && pendingLifecycle.action !== action) throw new Error('Inspect or retry the pending lifecycle request before selecting a different action.');
    if (!pendingLifecycle) pendingLifecycle = {operation_id:crypto.randomUUID(), action};
    const pending = pendingLifecycle;
    const epoch = showDialog('Checking lifecycle candidate', {operation_id:pending.operation_id, detail:'This explicit check may contact release servers. Applying requires a separate reviewed action.'});
    if (!lifecycleRequest || lifecycleRequest.pending !== pending) lifecycleRequest = {pending, promise:api('/api/lifecycle/prepare', pending)};
    const request = lifecycleRequest;
    try {
      const view = await request.promise;
      if (pendingLifecycle === pending) pendingLifecycle = null;
      if (dialogGeneration === epoch) displayLifecycle(view);
    } catch (error) {
      if (dialogGeneration !== epoch) return;
      showDialog('Lifecycle preview response unavailable', {operation_id:pending.operation_id, detail:'The request may have been saved. Keep this ID; retries retain the same requested action.', error:error.message});
      operationActions.append(button('Retry this lifecycle request', () => prepareLifecycle(pending.action), 'primary'),
        button('Inspect saved lifecycle request', () => requestDialog(() => api('/api/lifecycle/operation', {operation_id:pending.operation_id, action:'status'}), value => { if (pendingLifecycle === pending) pendingLifecycle = null; displayLifecycle(value); })),
        button('Leave this lifecycle request unapplied', () => { if (pendingLifecycle === pending) pendingLifecycle = null; dialog.close(); }));
    } finally { if (lifecycleRequest === request) lifecycleRequest = null; }
  }
  function displayLifecycle(view) {
    const context = operationContext('lifecycle', view.operation_id);
    renderDialog('Lifecycle operation', view);
    const id = context.id;
    operationContent.prepend(badge(view.phase), paragraph(view.next_action || 'Inspect the saved result.'), paragraph(`Operation ID: ${id}`, 'muted'));
    if (view.preview) {
      operationContent.prepend(row('Prepared candidate', view.preview.evidence, view.preview.candidate_version || (view.preview.candidate_sequence === null ? 'Unavailable' : `Sequence ${view.preview.candidate_sequence}`)),
        paragraph((view.preview.issues || []).join('\n'), view.preview.compatible ? 'muted' : 'notice'));
    }
    const action = name => act(context, name);
    if (view.phase === 'prepared') {
      if (view.preview?.compatible) operationActions.append(button('Apply reviewed lifecycle change', () => action('apply'), 'primary'));
      operationActions.append(button('Cancel lifecycle preview', () => action('cancel')));
    }
    operationActions.append(button('Refresh lifecycle status', () => action('status')));
    if (['accepted','verifying','publication_intent','published'].includes(view.phase)) {
      operationContent.append(paragraph('A binary update closes this service after active changes drain. The verified new binary opens a fresh dashboard. If it does not open, run tirith dashboard and inspect this operation ID.', 'notice'));
      pollTimer = setTimeout(() => action('status').catch(() => showError(new Error('The service may be restarting. Reopen with tirith dashboard and inspect lifecycle operation ' + id + '.'))), 2000);
    }
  }
  function invalidateDialog() { clearTimeout(pollTimer); activeOperation = null; return ++dialogGeneration; }
  function showDialog(title, value) { const epoch = invalidateDialog(); renderDialog(title, value); return epoch; }
  async function requestDialog(load, render) {
    const epoch = invalidateDialog();
    let value;
    try { value = await load(); }
    catch (error) { if (dialogGeneration === epoch) throw error; return; }
    if (dialogGeneration === epoch) render(value);
  }
  function operationContext(kind, id) {
    if (!activeOperation || activeOperation.kind !== kind || activeOperation.id !== id) {
      invalidateDialog();
      activeOperation = {kind, id, epoch:dialogGeneration, sequence:0, mutations:new Map()};
    }
    return activeOperation;
  }
  function currentOperation(context) { return dialog.open && activeOperation === context && dialogGeneration === context.epoch; }
  function renderDialog(title, value) {
    clearTimeout(pollTimer); document.querySelector('#operation-title').textContent = title;
    operationContent.replaceChildren(); operationActions.replaceChildren();
    if (value.kind === 'profile_preview') {
      operationContent.append(paragraph(`Personal profile: ${value.selection?.name || 'reset owned settings'}`), paragraph(`Destination: ${value.target}`, 'muted'), paragraph('Organization, project, remote, and incident restrictions still apply. No settings have changed yet.'));
      if (value.definition) operationContent.append(paragraph(value.definition.presentation));
      const table = element('table'); const head = element('tr'); for (const title of ['Setting', 'Before', 'After']) head.append(element('th', title)); table.append(head);
      for (const change of value.field_changes || []) { const row = element('tr'); row.append(element('td', change.field), element('td', change.before === null ? 'Not set' : JSON.stringify(change.before)), element('td', change.after === null ? 'Not set' : JSON.stringify(change.after))); table.append(row); }
      const scroll = element('div', undefined, 'table-scroll'); scroll.append(table); operationContent.append(scroll);
      if (value.custom_overrides?.length) operationContent.append(paragraph(`Preserved custom settings: ${value.custom_overrides.join(', ')}`, 'notice'));
    } else if (value.kind === 'personal_setting_preview') {
      operationContent.append(paragraph(`Personal setting: ${value.field}`), paragraph(`Destination: ${value.target}`, 'muted'), row('Current personal value', 'Before this change', JSON.stringify(value.before)), row('Proposed personal value', 'Null removes the personal override', JSON.stringify(value.after)), paragraph(value.constraints), paragraph('Refresh Protection after applying to inspect the effective result.'));
    } else if (value.semantics === 'trust_eligibility_only') {
      operationContent.append(paragraph('This explains whether an exception is eligible. Independent command blockers can remain; no command was evaluated.'));
    } else if (value.detail || value.error) {
      if (value.detail) operationContent.append(paragraph(value.detail, 'notice'));
      if (value.error) operationContent.append(paragraph(value.error, 'notice'));
    }
    operationContent.append(rawDetails('Inspect complete details', value));
    if (!dialog.open) dialog.showModal();
  }
  async function plan(intent) {
    if (pendingLifecycle) throw new Error('Inspect or retry the pending lifecycle request before preparing a settings change.');
    if (pendingPlan && JSON.stringify(pendingPlan.intent) !== JSON.stringify(intent)) {
      showDialog('Resolve the pending plan first', { operation_id: pendingPlan.operation_id, detail: 'The previous response was not received. Inspect or retry that exact stored request before preparing another change.' });
      pendingPlanActions(); return;
    }
    if (!pendingPlan) pendingPlan = { operation_id: crypto.randomUUID(), intent };
    await submitPendingPlan();
  }
  function pendingPlanActions(pending = pendingPlan) {
    operationActions.append(button('Retry the same request', () => { if (pendingPlan !== pending) throw new Error('This request is no longer pending. Inspect its saved ID.'); return submitPendingPlan(); }, 'primary'), button('Inspect stored operation', () => requestDialog(
      () => api('/api/operations', {operation_id:pending.operation_id, action:'status'}),
      result => { if (pendingPlan === pending) pendingPlan = null; showDialog('Saved operation', result); displayOperation(result); }
    )), button('Leave this plan unapplied', () => { if (pendingPlan === pending) pendingPlan = null; dialog.close(); }));
  }
  async function submitPendingPlan() {
    const pending = pendingPlan;
    if (!pending) throw new Error('No pending request remains. Inspect its saved operation ID.');
    const epoch = showDialog('Preparing change plan', {operation_id:pending.operation_id});
    if (!planRequest || planRequest.pending !== pending) planRequest = {pending, promise:api('/api/plans', {operation_id:pending.operation_id, ...pending.intent})};
    const request = planRequest;
    try {
      const value = await request.promise;
      if (pendingPlan === pending) pendingPlan = null;
      if (dialogGeneration !== epoch) return;
      showDialog(value.unchanged || value.operation === null ? 'No change required' : 'Review change plan', value);
      if (value.operation) {
        if (value.impact) value.operation.impact_review = value.impact;
        displayOperation(value.operation);
        if (value.kind === 'audit_rotation_plan' && value.preview) operationContent.prepend(paragraph(`Retain ${value.preview.retained_records} records (${value.preview.retained_bytes} bytes). ${value.preview.signed_segment ? 'The signed segment was verified.' : 'This segment has no signed-chain proof.'} Undo is available only before additional records are appended.`, 'notice'));
      }
    } catch (error) {
      if (dialogGeneration !== epoch) return;
      showDialog('Plan response unavailable', {operation_id:pending.operation_id, detail:'The request may have been stored. Retrying uses the same operation ID and original intent.', error:error.message});
      pendingPlanActions(pending);
    } finally { if (planRequest === request) planRequest = null; }
  }
  function displayOperation(operation) {
    const context = operationContext('settings', operation.operation_id); clearTimeout(pollTimer); operationContent.replaceChildren(badge(operation.no_op ? 'unchanged' : operation.state)); operationActions.replaceChildren();
    const descriptions = { planned: 'Review the destinations and changes below before applying.', running: 'The change continues if you close this page.', completed: 'The change was saved. Reload the relevant shell or host where required.', 'completed-with-recovery': 'The change was saved, with recovery material retained. Inspect the details before cleanup.', undone: 'The owned change was undone. Unrelated settings were preserved.', 'undone-with-recovery': 'Undo completed with recovery material retained.', 'refresh-required': 'Inputs changed. Refresh and review a new plan before continuing.', 'recovery-required': 'The operation needs recovery. Inspect its steps; do not assume every change was applied.', 'partially-applied': 'Only some steps completed. Inspect the recorded result before another action.', cancelled: 'The operation was cancelled.', 'cancel-requested': 'Cancellation was requested. Already completed steps remain recorded.' };
    operationContent.append(paragraph(operation.no_op ? 'No settings needed changing. This result is saved so retries cannot turn it into a different change.' : descriptions[operation.state] || 'Inspect the stored operation state.'));
    if (operation.detail) operationContent.append(paragraph(operation.detail, 'notice'));
    if (operation.irreversible) operationContent.append(paragraph('This operation permanently deletes retained records. A checkpoint and tombstone remain, but these records cannot be restored by undo.', 'notice'));
    if (operation.impact_review) {
      const impact = operation.impact_review;
      operationContent.append(paragraph(`Personal profile impact: ${impact.counts.unchanged} unchanged, ${impact.counts.more_restrictive} more restrictive, ${impact.counts.less_restrictive} less restrictive, ${impact.counts.unavailable} comparisons unavailable.`),
        paragraph(`Exception review: ${impact.counts.expired_exceptions} expired; ${impact.counts.unowned_exceptions} without verified ownership. Review captured ${impact.evaluated_at}.`, 'muted'),
        paragraph('This historical review does not prove execution, remote publication, or adoption by other clients. Missing evidence remains unavailable.', 'notice'),
        rawDetails('Inspect workflow impact, exception ownership and unavailable evidence', impact));
    }
    for (const step of operation.steps || []) operationContent.append(row(step.description, step.target, step.state));
    operationContent.append(rawDetails('Stored operation and recovery details', operation), paragraph(`Operation ID: ${context.id}`, 'muted'));
    if (!operation.no_op && !operation.presentation_incomplete && operation.state === 'planned') operationActions.append(button('Apply reviewed change', () => act(context, 'apply'), 'primary'));
    if (['planned','running','waiting','queued','cancel-requested'].includes(operation.state)) operationActions.append(button('Request cancellation', () => act(context, 'cancel')));
    if (!operation.irreversible && !operation.no_op && !operation.presentation_incomplete && ['completed','completed-with-recovery'].includes(operation.state)) operationActions.append(button('Undo owned change', () => act(context, 'undo')));
    operationActions.append(button('Refresh stored status', () => act(context, 'status')));
    if (['running','waiting','queued','cancel-requested'].includes(operation.state)) pollTimer = setTimeout(() => act(context, 'status').catch(showError), 1500);
  }
  async function act(context, action) {
    if (!currentOperation(context)) return;
    clearTimeout(pollTimer);
    if (action === 'status' && context.mutations.size) return;
    if (context.mutations.has(action)) return context.mutations.get(action);
    if (action !== 'status' && action !== 'cancel' && context.mutations.size) throw new Error('An action is being submitted for this operation. Its cancellation control remains available.');
    const sequence = ++context.sequence;
    const request = (async () => {
      const path = context.kind === 'lifecycle' ? '/api/lifecycle/operation' : '/api/operations';
      let value;
      try { value = await api(path, {operation_id:context.id, action}); }
      catch (error) { if (currentOperation(context) && sequence === context.sequence) throw error; return; }
      if (!currentOperation(context) || sequence !== context.sequence) return;
      if (value.operation_id !== context.id) throw new Error('The response identifies a different operation. Inspect the original stored ID.');
      if (context.kind === 'lifecycle') displayLifecycle(value); else displayOperation(value);
    })();
    if (action === 'status') return request;
    context.mutations.set(action, request);
    try { await request; }
    finally {
      context.mutations.delete(action);
      // A cancellation can overtake an apply response. Reconcile once all
      // submitted mutations settle instead of accepting the older snapshot.
      if (currentOperation(context) && !context.mutations.size) { clearTimeout(pollTimer); pollTimer = setTimeout(() => act(context, 'status').catch(showError), 0); }
    }
  }
  document.querySelector('#close-dialog').addEventListener('click', () => dialog.close()); dialog.addEventListener('close', invalidateDialog);
  async function navigate(page) {
    const run = ++generation; currentPage = page; notice.hidden = true;
    document.querySelector('#title').textContent = pages[page][0]; document.querySelector('#subtitle').textContent = pages[page][1];
    for (const node of document.querySelectorAll('[data-page]')) { if (node.dataset.page === page) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current'); }
    content.setAttribute('aria-busy', 'true');
    try { const nodes = await ({ overview, activity, protection, exceptions, integrations, settings })[page](); if (generation === run) content.replaceChildren(...nodes); }
    catch (error) { if (generation === run) { content.replaceChildren(paragraph('This view could not be refreshed. Previously submitted operations retain their stored state.', 'empty')); showError(error); } }
    finally { if (generation === run) content.setAttribute('aria-busy', 'false'); }
  }
  for (const node of document.querySelectorAll('[data-page]')) node.addEventListener('click', () => navigate(node.dataset.page));
  document.querySelector('.brand').addEventListener('click', event => { event.preventDefault(); navigate('overview'); });
  document.querySelector('#refresh').addEventListener('click', () => navigate(currentPage));
  async function start() {
    if (!/^[a-f0-9]{64}$/i.test(token)) throw new Error('Open this dashboard with tirith dashboard. The private session token is missing; it is never requested from another website.');
    const session = await api('/api/session'); csrf = session.csrf;
    document.querySelector('#session-state').textContent = `Local service ${session.version} · session expires in ${Math.floor(session.expires_in_seconds / 60)} minutes`;
    await navigate('overview');
  }
  start().catch(error => { content.replaceChildren(paragraph('The local session is unavailable. Reopen it from your terminal with tirith dashboard.', 'empty')); content.setAttribute('aria-busy','false'); showError(error); });
})();
