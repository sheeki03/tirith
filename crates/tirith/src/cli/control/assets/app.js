'use strict';
(() => {
  const content = document.querySelector('#content');
  const notice = document.querySelector('#notice');
  const dialog = document.querySelector('#operation-dialog');
  const operationContent = document.querySelector('#operation-content');
  const operationActions = document.querySelector('#operation-actions');
  // The launch URL carries a single-use sign-in code; it is exchanged once for
  // this tab's session and removed from the address bar and history.
  const code = new URLSearchParams(location.hash.slice(1)).get('code') || '';
  history.replaceState(null, '', location.pathname);
  let token = '', csrf = '', currentPage = 'overview', generation = 0, dialogGeneration = 0, activeOperation = null, pollTimer = null, pendingPlan = null, planRequest = null, threatDbRefresh = null;
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
  function commandRow(title, detail, command) {
    const code = element('code', command, 'command');
    const copy = button('Copy command', async () => {
      try { await navigator.clipboard.writeText(command); copy.textContent = 'Copied'; }
      catch { const range = document.createRange(); range.selectNodeContents(code); const selection = getSelection(); selection.removeAllRanges(); selection.addRange(range); throw new Error('Copy is unavailable here; the command is selected for manual copying.'); }
    });
    const node = row(title, detail, undefined, [copy]); node.firstChild.append(code); return node;
  }
  function showError(error) { notice.textContent = error.message || String(error); notice.hidden = false; }
  async function api(path, body, showDiagnostics = true, timeout = 35000) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
        headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'X-Tirith-CSRF': csrf }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const value = await response.json();
      if (!response.ok) { if (response.status === 401) document.querySelector('#session-state').textContent = 'Session expired — reopen with tirith dashboard'; throw new Error(value.error || 'Local request failed'); }
      if (showDiagnostics && value.diagnostics?.length) showError(new Error(value.diagnostics.join('\n')));
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
    const scope = select('Policy authority', [['user','Personal policy'],['org','Selected organization policy (file owner only)']]);
    const shell = select('Workflow shell', [['posix','Bash / Zsh / POSIX'],['fish','Fish'],['powershell','PowerShell']]);
    const commandsLabel = element('label','Representative commands, one per line'); const commands = element('textarea'); commands.rows = 5; commands.required = true; commands.maxLength = 12000; commandsLabel.append(commands);
    const interactive = field('Model interactive operation', 'checkbox'); interactive.input.checked = true;
    const submit = element('button','Prepare impact review','primary'); submit.type='submit';
    form.append(profile.label, scope.label, shell.label, commandsLabel, interactive.label, submit);
    form.addEventListener('submit', event => { event.preventDefault(); plan({kind:'policy_rollout', change:{profile:profile.input.value, scope:scope.input.value, commands:commands.value.split('\n').filter(value => value.trim()), shell:shell.input.value, interactive:interactive.input.checked}}).catch(showError); });
    section.append(paragraph('Compare explicit workflows against one captured policy context before explicitly changing a personal profile or the selected organization policy. Organization changes require the file-owning operator and refuse newer documents during activation or rollback. Commands are analyzed without execution. Missing runtime evidence remains unavailable; this review cannot establish fleet adoption or approve an operation.'), form); return section;
  }
  function advancedSettings(effective) {
    const section = panel('Advanced personal settings'); const form = element('form');
    if (effective.personal_controls_omitted) section.append(paragraph('Field summaries are unavailable because this policy response is large. The effective policy details remain available, and profile previews can still show their specific fields.', 'notice'));
    const setting = select('Setting', [['strict_warn', 'Require acknowledgement for warnings'], ['allow_bypass_env', 'Permit explicit interactive bypass'], ['allow_bypass_env_noninteractive', 'Permit explicit noninteractive bypass'], ['scan_require_complete', 'Require complete scan coverage'], ['env_guard_enabled', 'Environment guard'], ['context_guard_enabled', 'Context guard'], ['exec_guard_enabled', 'Executable guard'], ['hooks_guard_enabled', 'Repository hooks guard'], ['baseline_enabled', 'Baseline checks'], ['mcp_redact_injection', 'Redact injection in MCP output'], ['fail_mode', 'Behavior on internal check failure'], ['paranoia', 'Heuristic sensitivity'], ['rule_severity', 'Specific rule severity']]);
    const value = select('Personal value', []); const rule = field('Rule to customize', 'text', '', 'Exact rule ID'); const current = element('div');
    rule.input.maxLength = 128;
    const submit = element('button','Compare personal change','primary'); submit.type='submit';
    function showControl() {
      const selected = setting.input.value;
      const canonical = selected === 'scan_require_complete' ? 'scan.require_complete' : selected === 'rule_severity' ? `severity_overrides.${rule.input.value.trim()}` : selected;
      const control = effective.personal_controls?.[canonical];
      current.replaceChildren(policyFieldControl(control));
      const overridden = control?.personal_authority?.state === 'overridden';
      value.input.disabled = !control || overridden; submit.disabled = !control || overridden;
    }
    function choices() {
      value.input.replaceChildren();
      const options = setting.input.value === 'fail_mode' ? [['open', 'Open'], ['closed', 'Closed']] : setting.input.value === 'paranoia' ? [1,2,3,4].map(n => [String(n), String(n)]) : setting.input.value === 'rule_severity' ? [['LOW','Low'],['MEDIUM','Medium'],['HIGH','High'],['CRITICAL','Critical']] : [['true','Enabled'],['false','Disabled']];
      for (const [key, title] of [['reset', 'Remove personal override'], ...options]) { const option = element('option', title); option.value = key; value.input.append(option); }
      rule.label.hidden = setting.input.value !== 'rule_severity'; rule.input.required = !rule.label.hidden;
      showControl();
    }
    setting.input.addEventListener('change', choices); choices();
    rule.input.addEventListener('input', showControl);
    form.append(setting.label, value.label, rule.label, current, submit);
    form.addEventListener('submit', event => { event.preventDefault(); const selected = value.input.value;
      const change = {setting:setting.input.value, value:selected === 'reset' ? null : selected === 'true' ? true : selected === 'false' ? false : setting.input.value === 'paranoia' ? Number(selected) : selected};
      if (setting.input.value === 'rule_severity') change.rule = rule.input.value.trim();
      requestDialog(() => api('/api/settings/preview', change), preview => { showDialog('Review personal setting', preview); personalPlanButton(preview, () => plan({kind:'personal_setting',change})); }).catch(showError);
    });
    section.append(paragraph('These changes apply to your personal policy. Profile changes and resets preserve explicit overrides. Removal restores the value inherited from other policy sources.'), form); return section;
  }
  async function previewProfile(profile) {
    return requestDialog(() => api('/api/profile/preview', {profile}), value => {
      showDialog('Review personal profile', value);
      personalPlanButton(value, () => plan({kind:'profile', profile}));
    });
  }
  function policyValue(value) { return value === undefined ? 'Unavailable' : value === null ? 'No policy override' : JSON.stringify(value); }
  function policySource(source) {
    const names = {default:'Built-in defaults', user:'Personal policy', org:'Organization policy', repo:'Repository policy', remote:'Remote policy', remote_cache:'Cached remote policy', incident:'Incident policy', not_set:'No policy override'};
    const name = names[source?.kind] || (source?.kind ? String(source.kind).replace(/[_-]/g, ' ') : 'Source unavailable');
    return source?.path ? `${name}: ${source.path}` : name;
  }
  function policyFieldControl(control) {
    const node = element('div', undefined, 'policy-field-control');
    if (!control) { node.append(paragraph('Field authority is unavailable. Review the current policy before changing this setting.', 'notice')); return node; }
    node.append(row('Current effective value', policySource(control.effective_source), control.effective_value_omitted ? 'Value too large to display here' : policyValue(control.effective_value)));
    if (control.effective_value_omitted) node.append(paragraph('The current value is omitted from this field summary. Inspect the effective policy details for the full redacted value.', 'muted'));
    const authority = control.personal_authority;
    if (authority?.state === 'overridden') {
      node.append(paragraph(`Managed by ${policySource(authority.governing_source)}. A personal change cannot change the effective value. Use the managing policy or contact its owner.`, 'notice'));
    } else if (authority?.state === 'effective') {
      node.append(paragraph('Your personal policy can affect this setting. Repository and incident constraints still apply.', 'muted'));
    } else {
      node.append(paragraph('Whether a personal change can affect this setting is unknown. The change will be checked again before apply.', 'notice'));
    }
    if (authority?.reason) node.append(paragraph(authority.reason, 'muted'));
    if (control.contributions?.length) {
      const details = element('details'); details.append(element('summary', 'Captured policy contributions'));
      for (const contribution of control.contributions.slice(0, 8)) details.append(paragraph(`${policySource(contribution.source)}: ${contribution.reason}`));
      details.append(paragraph('Contributions include earlier and unchanged declarations; they do not each establish a current lock.', 'muted'));
      node.append(details);
    }
    if (control.contributions?.length > 8 || control.contributions_omitted) node.append(paragraph('Additional contributions are omitted from this view.', 'muted'));
    if (control.neutralized_settings?.length) node.append(paragraph('Rejected repository preferences are recorded in the details. They do not lock your personal setting.', 'muted'));
    if (control.neutralized_settings_omitted) node.append(paragraph('Additional rejected repository preferences are omitted from this view.', 'muted'));
    if (control.source_paths_omitted) node.append(paragraph('Some source paths are omitted to keep this response bounded.', 'muted'));
    return node;
  }
  function personalPlanButton(preview, create) {
    const controls = preview.control ? [preview.control] : (preview.field_changes || []).map(change => change.control);
    const overridden = controls.some(control => control?.personal_authority?.state === 'overridden');
    const action = button('Create change plan', create, 'primary'); action.disabled = overridden;
    operationActions.append(action);
    if (overridden) operationContent.append(paragraph('This personal policy is overridden by a managing authority. No personal change plan is available here.', 'notice'));
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
    const recommendedClaude = field('Include Claude Code', 'checkbox');
    recommended.append(paragraph('Review one plan for your personal shell integration, protection profile and any selected agent. Existing manual settings are preserved. A fresh shell and its verification handshake are required after applying.'), recommendedShell.label, recommendedProfile.label, recommendedClaude.label,
      paragraph('Configures the Claude Code hook in this plan; reload Claude Code, then verify. Saved configuration does not prove a running agent is protected.', 'muted'),
      button('Review personal setup', () => {
        if (!recommendedShell.input.value) throw new Error('Choose the shell whose personal startup configuration you intend to change.');
        return plan({kind:'recommended_setup', change:{scope:'user', shell:recommendedShell.input.value, profile:recommendedProfile.input.value, agents:recommendedClaude.input.checked ? ['claude-code'] : []}});
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
    install.append(paragraph('Updates run in a terminal, so the owning installer or `tirith update` verifies the release and can ask for any confirmation it needs. This dashboard does not replace the binary.'));
    if (lifecycle.upgrade_guidance) install.append(commandRow('To upgrade', `Installed through ${lifecycle.install_method}; use that channel.`, lifecycle.upgrade_guidance));
    else if (lifecycle.self_replaceable) install.append(commandRow('To upgrade', 'Verifies the signed release before replacing this binary.', 'tirith update'),
      commandRow('To roll back', 'Restores the previous binary kept by the last `tirith update`, when one was saved.', 'tirith update --rollback'));
    else install.append(commandRow('To upgrade', 'The installation channel is not known. Inspect it, then use the installer that owns this binary.', 'tirith version --provenance'));
    const sources = panel('Threat intelligence freshness'); sources.append(threatDbFreshness(fresh));
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
    for (const operation of jobs.operations) recent.append(row(operation.kind || 'Saved change', operation.operation_id, operation.no_op ? 'unchanged' : shownState(operation), [button('Open saved operation', () => requestDialog(() => api('/api/operations', {operation_id:operation.operation_id, action:'status'}), stored => { showDialog('Saved operation', stored); displayOperation(stored); }))]));
    recent.append(rawDetails('Inspect inventory coverage', jobs.coverage));
    return [install, approval, sources, await teamConnectionPanel(), await teamEnrollmentPanel(), teamRolloutPanel(), retention, recent, supportPanel(), local, exportPanel];
  }
  async function teamConnectionPanel() {
    const section = panel('Optional team policy connection');
    section.append(paragraph('Connect only if you use a team policy server. Personal protection needs no connection or administrator access. Saving a connection does not enable team policy or enroll this device.'));
    const summary = element('div'); section.append(summary);
    let selected = null;
    function render(view) {
      selected = view.connection;
      summary.replaceChildren(row('Saved connection', selected.endpoint_origin || 'No authority selected', selected.configured ? 'Configured' : 'Not configured'));
      if (selected.connection_id) summary.append(row('Connection ID', selected.connection_id), row('Authority ID', selected.authority_id), row('Policy ID', selected.policy_id));
      if (selected.authentication === 'authenticated_now') {
        summary.append(row('Authenticated role', selected.role || 'Unavailable'), row('Credential expiry', new Date(selected.credential_expires_unix_ms).toISOString()));
      } else summary.append(paragraph('Role and credential expiry are unavailable until an explicit authentication check.'));
      if (view.storage === 'saved_with_recovery') summary.append(paragraph('The connection was saved, but private recovery data was retained. Inspect local status before another change.', 'notice'));
      replace.input.checked = false;
    }
    const server = field('Server URL', 'url', '', 'https://policy.example.com');
    const authority = field('Authority UUID'); const policy = field('Policy UUID');
    const credential = field('Selected private credential file', 'text', '', 'Absolute local file path');
    const addresses = field('Optional fixed addresses', 'text', '', 'Up to eight IP addresses, separated by commas');
    const ca = field('Optional private CA certificate file', 'text', '', 'Absolute local file path');
    const replace = field('Replace the currently displayed connection', 'checkbox');
    server.input.maxLength = 2048; authority.input.maxLength = policy.input.maxLength = 36;
    credential.input.maxLength = ca.input.maxLength = 8192; addresses.input.maxLength = 512;
    credential.input.autocomplete = ca.input.autocomplete = 'off';
    section.append(button('Refresh local status', async () => render(await api('/api/team/connection'))), button('Authenticate selected connection', async () => render(await api('/api/team/connection/status', {refresh:true}))));
    section.append(server.label, authority.label, policy.label, credential.label, addresses.label, ca.label, replace.label);
    section.append(paragraph('The credential is read from the file you select. The token and CA contents are never displayed here. Connecting contacts the selected server to verify both UUID pins before saving.'));
    section.append(button('Authenticate and save connection', async () => {
      if (!selected) throw new Error('Load current connection status first.');
      const pinned = addresses.input.value.split(',').map(v => v.trim()).filter(Boolean);
      if (pinned.length > 8) throw new Error('Select no more than eight fixed addresses.');
      const request = {server_url:server.input.value.trim(), authority_id:authority.input.value.trim(), policy_id:policy.input.value.trim(), credential_file:credential.input.value.trim(), private_ca_file:ca.input.value.trim() || null, pinned_addresses:pinned, expected_connection_id:selected.configured && replace.input.checked ? selected.connection_id : null};
      try { render(await api('/api/team/connection/connect', request)); }
      finally { credential.input.value = ''; ca.input.value = ''; }
    }, 'primary'));
    const disconnect = field('Disconnect the currently displayed connection', 'checkbox'); section.append(disconnect.label);
    section.append(button('Disconnect', async () => {
      if (!selected?.connection_id || !disconnect.input.checked) throw new Error('Inspect and acknowledge the displayed connection before disconnecting.');
      try { render(await api('/api/team/connection/disconnect', {expected_connection_id:selected.connection_id})); }
      finally { disconnect.input.checked = false; }
    }));
    try { render(await api('/api/team/connection')); } catch (error) { summary.append(paragraph(error.message || 'Private connection state is unavailable.', 'notice')); }
    return section;
  }
  async function teamEnrollmentPanel() {
    const section = panel('Optional team Runtime enrollment');
    section.append(paragraph('Team policy stays off until you explicitly activate it. Activation and sync contact the saved authority using a Client credential and validate the fetched policy with repository and local restrictions. They do not send Applied reports.'));
    const summary = element('div'); const result = element('div'); section.append(summary, result);
    let current = null;
    const activate = field('Activate the displayed connection, replacing the displayed activation if present', 'checkbox');
    const disable = field('Disable the displayed activation', 'checkbox');
    const repair = field('Remove only the enrollment that is currently malformed when this action runs', 'checkbox');
    const abandon = field('Archive the displayed unresolved report; its server outcome remains unknown', 'checkbox');
    function render(view) {
      current = view;
      summary.replaceChildren(row('Local Runtime', view.state), row('Selected connection ID', view.selected_connection_id || 'None'), row('Activation ID', view.activation_id || 'None'));
      const evidence = view.runtime_evidence;
      if (evidence) summary.append(row('Cached revision', evidence.revision), row('Client ID', evidence.client_id), row('Fetched', new Date(evidence.fetched_unix_ms).toISOString()));
      if (view.state === 'runtime_refused') summary.append(paragraph('Runtime is blocked by stale, invalid, changed, or competing policy inputs. Sync requires the same connection; exact disable remains available offline.', 'notice'));
      if (view.state === 'malformed' || view.state === 'storage_unavailable') summary.append(paragraph('Enrollment could not be safely admitted. Its bytes were preserved; automatic replacement is unavailable. Explicit removal applies only if the record is still malformed when the action captures it.', 'notice'));
      if (view.report?.report_id) summary.append(row('Stored report', view.report.report_id, view.report.state));
      const archives = view.report?.archived_reports || [];
      if (archives.length) summary.append(paragraph(`${archives.length} of 4 bounded report archive slots are in use.`));
      for (const archived of archives) {
        summary.append(row('Archived report', archived.report_id, archived.state), row('Archive ID', archived.archive_id));
        summary.append(button('Reconcile this archived report', () => perform('/api/team/enrollment/reconcile', {report_id:archived.report_id, archive_id:archived.archive_id})));
      }
      summary.append(paragraph(view.notice)); activate.input.checked = false; disable.input.checked = false; repair.input.checked = false; abandon.input.checked = false;
    }
    async function refresh() { render(await api('/api/team/enrollment')); }
    function selected() {
      if (!current?.selected_connection_id) throw new Error('Load a saved connection before this action.');
      return {expected_connection_id:current.selected_connection_id, expected_activation_id:current.activation_id || null};
    }
    function enrolled() { const request = selected(); if (!request.expected_activation_id) throw new Error('Load the exact activation before this action.'); return request; }
    async function perform(path, request) {
      // Preserve the returned storage outcome even when the subsequent local
      // refresh cannot complete. Never auto-retry a report after a transport error.
      const view = await api(path, request);
      result.replaceChildren(paragraph(view.notice || 'Operation completed.'), rawDetails('Inspect operation and storage outcome', view));
      if (view.local_write?.includes('unconfirmed') || view.outcome?.includes('unknown') || view.outcome === 'pending_not_sent') result.prepend(paragraph('Completion is unconfirmed. Inspect the retained local state before another explicit action.', 'notice'));
      await refresh();
    }
    section.append(button('Refresh local enrollment status', refresh), activate.label,
      button('Fetch, validate, and activate', async () => {
        if (!activate.input.checked) throw new Error('Acknowledge the displayed connection and activation first.');
        const request = selected(); activate.input.checked = false;
        await perform('/api/team/enrollment/activate', request);
      }),
      button('Fetch and sync this activation', () => perform('/api/team/enrollment/sync', enrolled())), disable.label,
      button('Disable this activation offline', async () => {
        if (!current?.activation_id || !disable.input.checked) throw new Error('Acknowledge the displayed activation first.');
        const request = {expected_activation_id:current.activation_id}; disable.input.checked = false;
        await perform('/api/team/enrollment/disable', request);
      }),
      repair.label,
      button('Remove currently malformed enrollment', async () => {
        if (!repair.input.checked) throw new Error('Acknowledge removal of the currently malformed enrollment first.');
        repair.input.checked = false;
        await perform('/api/team/enrollment/repair', {remove_malformed:true});
      }),
      paragraph('Reporting resolves actual Runtime and authenticates the same Client. The exact report is saved privately before sending. Uncertain outcomes keep that request for explicit retry, without a new sequence.'),
      button('Report actual Runtime', () => perform('/api/team/enrollment/report', {...enrolled(), retry_report_id:null})),
      button('Reconcile stored report without resending', () => {
        if (!current?.report?.report_id) throw new Error('Load an exact stored report first.');
        return perform('/api/team/enrollment/reconcile', {report_id:current.report.report_id, archive_id:current.report.archive_id || null});
      }),
      paragraph('Read-only reconciliation checks the exact request retained by the server. An unavailable or superseded report stays unknown. If Runtime has changed, explicit abandonment preserves the old request locally and permits a new report after fresh authentication; a late server commit can still cause a conflict.'),
      abandon.label,
      button('Archive unresolved report locally', async () => {
        if (current?.report?.state !== 'pending' || !abandon.input.checked) throw new Error('Inspect and acknowledge the exact pending report first.');
        const request = {report_id:current.report.report_id, acknowledge_unknown_outcome:true}; abandon.input.checked = false;
        await perform('/api/team/enrollment/abandon', request);
      }),
      button('Retry exact pending report', () => {
        if (current?.report?.state !== 'pending' || !current.report.report_id) throw new Error('Load an exact pending report before retrying.');
        return perform('/api/team/enrollment/report', {...enrolled(), retry_report_id:current.report.report_id});
      }));
    try { await refresh(); } catch (error) { summary.append(paragraph(error.message || 'Local enrollment status is unavailable.', 'notice')); }
    return section;
  }
  function teamRolloutPanel() {
    const section = panel('Review a team policy rollout');
    section.append(paragraph('A publisher can review selected workflows, then publish to the exact server revision shown. Device activation is separate. This panel contacts your server only after an explicit action.'));
    const yamlLabel = element('label', 'Proposed policy YAML'); const yaml = element('textarea'); yaml.rows = 6; yaml.maxLength = 12000; yaml.setAttribute('aria-label', 'Proposed policy YAML'); yamlLabel.append(yaml);
    const workflowLabel = element('label', 'Workflows, one command per line'); const workflows = element('textarea'); workflows.rows = 4; workflows.maxLength = 12000; workflows.setAttribute('aria-label', 'Team policy workflows'); workflowLabel.append(workflows);
    const shell = select('Workflow shell', [['posix','Bash / Zsh / POSIX'],['fish','Fish'],['powershell','PowerShell'],['cmd','Windows CMD']]);
    const interactive = field('Workflows run interactively', 'checkbox');
    const id = field('Stored rollout operation ID'); id.input.maxLength = 36;
    let pending = null;
    section.append(yamlLabel, workflowLabel, shell.label, interactive.label,
      paragraph('Browser requests are limited to 16 KiB in total. Use the CLI for larger policy documents. Workflows are inspected; these commands are never executed.', 'muted'),
      button('Prepare impact review', async () => {
        if (!pending) pending = {operation_id:crypto.randomUUID(),change:{yaml:yaml.value,commands:workflows.value.split('\n').map(c => c.trim()).filter(Boolean),shell:shell.input.value,interactive:interactive.input.checked}};
        id.input.value = pending.operation_id;
        if (new TextEncoder().encode(JSON.stringify(pending)).length > 16000) { pending = null; throw new Error('This review exceeds the browser request limit. Use tirith policy team rollout prepare with a local policy file.'); }
        const selected = pending;
        await requestDialog(() => api('/api/team/rollout/prepare', selected), view => { if (pending === selected) pending = null; yaml.value = ''; showTeamRollout(view); });
      }, 'primary'), id.label,
      button('Inspect stored review', () => requestDialog(() => api('/api/team/rollout/show',{operation_id:id.input.value.trim(),refresh:false}), view => { if (pending?.operation_id === view.operation_id) pending = null; showTeamRollout(view); })),
      button('Refresh server operation status', () => requestDialog(() => api('/api/team/rollout/show',{operation_id:id.input.value.trim(),refresh:true}), showTeamRollout)),
      button('Fetch client rollout reports', () => requestDialog(() => api('/api/team/rollout/fleet',{}), view => {
        showDialog('Team client reports', view); operationContent.prepend(paragraph(view.notice, 'notice'));
        for (const client of view.fleet?.clients || []) operationContent.append(row(client.client_id, client.report ? `Reported revision ${client.report.applied_revision}` : 'No report received', client.status));
      })));
    section.append(paragraph('If a response is lost, keep the displayed operation ID and inspect it before preparing another review. No review or retry approves a policy or exception automatically.', 'muted'));
    return section;
  }
  function showTeamRollout(view) {
    showDialog(view.kind === 'rollback' ? 'Review team policy rollback' : 'Review team policy publication', view);
    operationContent.prepend(paragraph(view.notice, 'notice'), row('Operation', view.operation_id, view.phase), row('Expected server revision', view.expected_revision), row('Reviewed workflows', `${view.impact_review?.workflows?.length || 0} selected workflows`, view.historical_evidence?.review_freshness || 'Unavailable'));
    const observations = {
      authenticated_exact_intent_observation: 'The server confirmed the outcome for this exact request.',
      server_has_no_record_at_this_observation: 'The server has no matching record at this time.',
      submission_journal_durability_unconfirmed_no_server_mutation_sent: 'The local pending request could not be confirmed durable. No server change was sent.',
      submission_outcome_not_confirmed: 'The server outcome is uncertain. Refresh this exact request before another action.'
    };
    if (view.current_observation) operationContent.append(paragraph(observations[view.current_observation] || 'The server outcome could not be confirmed.', 'notice'));
    if (view.last_operation_observation) operationContent.append(row('Server outcome', view.last_operation_observation.failure_code || view.last_operation_observation.published_revision || 'No committed revision', view.last_operation_observation.outcome));
    for (const workflow of view.impact_review?.workflows || []) operationContent.append(row(workflow.id, `${workflow.before} → ${workflow.proposed}`, workflow.comparison_available ? workflow.change : 'Comparison unavailable'));
    for (const exception of view.impact_review?.exceptions || []) operationContent.append(row(exception.id, exception.expires_at ? `Expires ${exception.expires_at}` : 'No expiry recorded', exception.proposed));
    const request = {operation_id:view.operation_id,review_id:view.review_id,rollback:view.kind === 'rollback'};
    if (['prepared','submitted'].includes(view.phase) && view.historical_evidence?.review_freshness === 'recent') {
      const reviewed = field('I reviewed this policy, its workflow impact and unavailable evidence', 'checkbox'); operationContent.append(reviewed.label);
      operationActions.append(button(view.kind === 'rollback' ? 'Apply reviewed rollback' : 'Publish reviewed policy', async () => {
        if (!reviewed.input.checked) throw new Error('Review and acknowledge this exact policy before submitting it.');
        await requestDialog(() => api('/api/team/rollout/apply',request),showTeamRollout);
      }, 'primary'));
    }
    operationActions.append(button('Refresh this operation', () => requestDialog(() => api('/api/team/rollout/show',{operation_id:view.operation_id,refresh:true}),showTeamRollout)));
    if (view.kind === 'publication' && view.last_operation_observation?.rollback_eligible) {
      const operationId = crypto.randomUUID();
      operationActions.append(button('Prepare rollback review', () => requestDialog(() => api('/api/team/rollout/rollback-plan',{operation_id:operationId,publication_id:view.operation_id}),showTeamRollout)));
      operationContent.append(paragraph('Rollback availability is rechecked on the server. Another publication or an expired window prevents rollback.', 'muted'));
    }
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
  function threatDbFreshness(fresh, outcome = '') {
    const section = element('div');
    const interval = fresh.refresh_interval_hours ? `Refreshes automatically about every ${fresh.refresh_interval_hours} hours while protection runs.` : 'Automatic refresh is disabled (auto_update_hours: 0).';
    const state = element('p', outcome, 'notice'); state.hidden = !outcome; state.setAttribute('role', 'status');
    const refresh = button('Refresh threat DB now', async () => {
      if (!threatDbRefresh) threatDbRefresh = api('/api/threatdb/refresh', {}, true, 300000).finally(() => { threatDbRefresh = null; });
      await follow(threatDbRefresh);
    }, 'primary');
    // One refresh runs at a time; a view opened while it runs follows it.
    async function follow(pending) {
      state.textContent = 'Refreshing the signed threat database…'; state.hidden = false; refresh.disabled = true;
      try {
        const result = await pending;
        // Report in place; a late result never opens or replaces a dialog.
        if (section.isConnected) section.replaceWith(threatDbFreshness(result.freshness, 'Refreshed: the signed threat database is current. Supplemental feed results appear under the last update.'));
        return result;
      } catch (error) {
        state.textContent = `Refresh did not complete: ${error.message}`;
        throw error;
      } finally { refresh.disabled = false; }
    }
    if (threatDbRefresh) follow(threatDbRefresh).catch(() => {});
    section.append(row('Installed database', fresh.error || 'A signed publication can contain older source data; inspect each dimension.', fresh.status),
      row('Last update', fresh.last_update ? `${fresh.last_update.status || 'unknown'} · ${fresh.last_update.phase || 'unknown phase'}` : 'No update has been recorded.', fresh.age_hours == null ? 'Unknown age' : `${Math.round(fresh.age_hours)} h old`),
      paragraph(interval, 'muted'), state, refresh,
      commandRow('From a terminal', 'Runs the same signed update as this button.', 'tirith threat-db update'),
      rawDetails('Inspect publication, source age, and pin adoption', fresh));
    return section;
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
      const table = element('table', undefined, 'profile-diff'); const titles = ['Setting', 'Personal before', 'Personal after', 'Effective now and source'];
      const head = element('tr'); for (const title of titles) head.append(element('th', title));
      const heading = element('thead'); heading.append(head); table.append(heading); const body = element('tbody'); table.append(body);
      for (const change of value.field_changes || []) {
        const entry = element('tr'); const effective = element('td'); effective.append(policyFieldControl(change.control));
        const cells = [element('td', change.field), element('td', policyValue(change.before)), element('td', policyValue(change.after)), effective];
        cells.forEach((cell, index) => { cell.dataset.label = titles[index]; entry.append(cell); }); body.append(entry);
      }
      const scroll = element('div', undefined, 'table-scroll'); scroll.append(table); operationContent.append(scroll);
      operationContent.append(paragraph('The proposed values are personal preferences. The effective result remains unverified until the change is applied and the resolver reads it back.', 'notice'));
      if (value.custom_overrides?.length) operationContent.append(paragraph(`Preserved custom settings: ${value.custom_overrides.join(', ')}`, 'notice'));
    } else if (value.kind === 'personal_setting_preview') {
      operationContent.append(paragraph(`Personal setting: ${value.field}`), paragraph(`Destination: ${value.target}`, 'muted'), row('Current personal value', 'Before this change', policyValue(value.before)), row('Proposed personal value', 'Removing an override restores inherited behavior', policyValue(value.after)), policyFieldControl(value.control), paragraph('The effective result will be read back after apply; a saved personal value does not prove it took effect.', 'notice'));
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
        if (value.impact) {
          value.operation.impact_review = value.impact;
          value.operation.impact_observation = value.live?.impact_observation;
        }
        displayOperation(value.operation, value.preview);
        if (value.kind === 'audit_rotation_plan' && value.preview) operationContent.prepend(paragraph(`Retain ${value.preview.retained_records} records (${value.preview.retained_bytes} bytes). ${value.preview.signed_segment ? 'The signed segment was verified.' : 'This segment has no signed-chain proof.'} Undo is available only before additional records are appended.`, 'notice'));
      }
    } catch (error) {
      if (dialogGeneration !== epoch) return;
      showDialog('Plan response unavailable', {operation_id:pending.operation_id, detail:'The request may have been stored. Retrying uses the same operation ID and original intent.', error:error.message});
      pendingPlanActions(pending);
    } finally { if (planRequest === request) planRequest = null; }
  }
  // A finished apply or undo (and each of its steps) that retained platform
  // recovery material carries `recovery`; show it as part of the state label.
  function shownState(item) { return item.recovery ? `${item.state}-with-recovery` : item.state; }
  function displayOperation(operation, preview) {
    const context = operationContext('settings', operation.operation_id); clearTimeout(pollTimer); operationContent.replaceChildren(badge(operation.no_op ? 'unchanged' : shownState(operation))); operationActions.replaceChildren();
    context.readbackSequence = (context.readbackSequence || 0) + 1;
    if (preview) context.policyFields = preview.field ? [preview.field] : (preview.field_changes || []).map(change => change.field);
    const descriptions = { planned: 'Review the destinations and changes below before applying.', running: 'The change continues if you close this page.', completed: 'The change was saved. Reload the relevant shell or host where required.', 'completed-with-recovery': 'The change was saved, with recovery material retained. Inspect the details before cleanup.', undone: 'The owned change was undone. Unrelated settings were preserved.', 'undone-with-recovery': 'Undo completed with recovery material retained.', 'refresh-required': 'Inputs changed. Refresh and review a new plan before continuing.', 'recovery-required': 'The operation needs recovery. Inspect its steps; do not assume every change was applied.', 'partially-applied': 'Only some steps completed. Inspect the recorded result before another action.', cancelled: 'The operation was cancelled.', 'cancel-requested': 'Cancellation was requested. Already completed steps remain recorded.' };
    operationContent.append(paragraph(operation.no_op ? 'No settings needed changing. This result is saved so retries cannot turn it into a different change.' : descriptions[shownState(operation)] || 'Inspect the stored operation state.'));
    if (operation.detail) operationContent.append(paragraph(operation.detail, 'notice'));
    if (operation.irreversible) operationContent.append(paragraph('This operation permanently deletes retained records. A checkpoint and tombstone remain, but these records cannot be restored by undo.', 'notice'));
    if (operation.impact_review) {
      const impact = operation.impact_review;
      const authority = {personal_user:'Personal', local_managed:'Organization', remote_managed:'Remote organization'}[impact.scope] || 'Selected authority';
      operationContent.append(paragraph(`${authority} profile impact: ${impact.counts.unchanged} unchanged, ${impact.counts.more_restrictive} more restrictive, ${impact.counts.less_restrictive} less restrictive, ${impact.counts.unavailable} comparisons unavailable.`),
        paragraph(`Exception review: ${impact.counts.expired_exceptions} expired; ${impact.counts.unowned_exceptions} without verified ownership. Review captured ${impact.evaluated_at}.`, 'muted'),
        paragraph('This historical review does not prove execution, remote publication, or adoption by other clients. Missing evidence remains unavailable.', 'notice'),
        rawDetails('Inspect workflow impact, exception ownership and unavailable evidence', impact));
      const observation = operation.impact_observation;
      if (observation?.schema_version === 1) {
        const freshness = {recent:'Recent', stale:'Stale', invalid_timestamp:'Future-dated review'}[observation.review_freshness] || 'Unavailable';
        operationContent.append(paragraph(`Historical evidence age: ${freshness}. Checked ${observation.checked_at}.`, 'muted'));
        if (observation.expiries_reached_since_review !== null) operationContent.append(paragraph(`Recorded exceptions whose expiry time has passed since this review: ${observation.expiries_reached_since_review}.`, 'muted'));
        operationContent.append(paragraph(`Captured client timestamps: ${observation.stale_client_timestamps} stale, ${observation.future_client_timestamps} future-dated, ${observation.missing_client_timestamps} missing. These age checks do not contact clients or recheck current exceptions.`, 'notice'));
      } else {
        operationContent.append(paragraph('Read-time evidence age is unavailable. Inspect the captured timestamps; current exceptions and client adoption have not been rechecked.', 'notice'));
      }
    }
    for (const step of operation.steps || []) operationContent.append(row(step.description, step.target, shownState(step)));
    operationContent.append(rawDetails('Stored operation and recovery details', operation), paragraph(`Operation ID: ${context.id}`, 'muted'));
    if (['set-profile','set-managed-profile','set-personal-setting','recommended-setup','import-policy'].includes(operation.kind) && ['completed','undone'].includes(operation.state)) {
      const readback = panel('Current effective readback'); readback.append(paragraph('Reading current policy…', 'muted')); operationContent.append(readback);
      readEffectivePolicy(context, context.readbackSequence, readback);
    }
    if (!operation.no_op && !operation.presentation_incomplete && operation.state === 'planned') operationActions.append(button('Apply reviewed change', () => act(context, 'apply'), 'primary'));
    if (['planned','running','waiting','queued','cancel-requested'].includes(operation.state)) operationActions.append(button('Request cancellation', () => act(context, 'cancel')));
    if (!operation.irreversible && !operation.no_op && !operation.presentation_incomplete && operation.state === 'completed') operationActions.append(button('Undo owned change', () => act(context, 'undo')));
    operationActions.append(button('Refresh stored status', () => act(context, 'status')));
    if (['running','waiting','queued','cancel-requested'].includes(operation.state)) pollTimer = setTimeout(() => act(context, 'status').catch(showError), 1500);
  }
  async function readEffectivePolicy(context, sequence, target) {
    const actionSequence = context.sequence;
    try {
      const effective = await api('/api/policy', undefined, false);
      if (!currentOperation(context) || context.sequence !== actionSequence || context.readbackSequence !== sequence || !target.isConnected) return;
      target.replaceChildren(element('h2', 'Current effective readback'), paragraph('These are the resolver’s current values. Other policy changes may have occurred since this operation.', 'muted'));
      if (effective.diagnostics?.length) target.append(paragraph(effective.diagnostics.join('\n'), 'notice'));
      if (effective.personal_controls_omitted) target.append(paragraph('Field summaries are unavailable because this policy response is large. Inspect the current effective policy details below.', 'notice'));
      const fields = context.policyFields?.length ? context.policyFields : ['strict_warn','allow_bypass_env','fail_mode','paranoia','scan.require_complete'];
      for (const field of [...new Set(fields)].slice(0, 32)) {
        const control = effective.personal_controls?.[field];
        target.append(element('h3', field), policyFieldControl(control));
      }
      target.append(rawDetails('Inspect current effective policy and sources', effective));
    } catch (error) {
      if (!currentOperation(context) || context.sequence !== actionSequence || context.readbackSequence !== sequence || !target.isConnected) return;
      target.replaceChildren(element('h2', 'Current effective readback'), paragraph(`Current effective state is unavailable: ${error.message}. The stored operation result is unchanged.`, 'notice'));
    }
  }
  async function act(context, action) {
    if (!currentOperation(context)) return;
    clearTimeout(pollTimer);
    if (action === 'status' && context.mutations.size) return;
    if (context.mutations.has(action)) return context.mutations.get(action);
    if (action !== 'status' && action !== 'cancel' && context.mutations.size) throw new Error('An action is being submitted for this operation. Its cancellation control remains available.');
    const sequence = ++context.sequence;
    const request = (async () => {
      let value;
      try { value = await api('/api/operations', {operation_id:context.id, action}); }
      catch (error) { if (currentOperation(context) && sequence === context.sequence) throw error; return; }
      if (!currentOperation(context) || sequence !== context.sequence) return;
      if (value.operation_id !== context.id) throw new Error('The response identifies a different operation. Inspect the original stored ID.');
      displayOperation(value);
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
  async function signIn() {
    const response = await fetch('/api/session/exchange', { method: 'POST', cache: 'no-store', credentials: 'omit', redirect: 'error',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'This dashboard link was already used or has expired. Run tirith dashboard again.');
    token = value.token; csrf = value.csrf;
    return value;
  }
  async function start() {
    if (!/^[a-f0-9]{64}$/i.test(code)) throw new Error('Open this dashboard with tirith dashboard. Each link signs in once; it is never requested from another website.');
    const session = await signIn();
    document.querySelector('#session-state').textContent = `Local service ${session.version} · session expires in ${Math.floor(session.expires_in_seconds / 60)} minutes`;
    await navigate('overview');
  }
  start().catch(error => { content.replaceChildren(paragraph('The local session is unavailable. Reopen it from your terminal with tirith dashboard.', 'empty')); content.setAttribute('aria-busy','false'); showError(error); });
})();
