# Local dashboard design

The dashboard is a local workbench for someone protecting a terminal or agent.
Its first job is to distinguish configured protection from observed interception
and offer the appropriate next action. It must work without an account, network
font, CDN, or frontend runtime installed on the user's computer.

The visual system uses paper white `#ffffff`, cool background `#f5f7fc`, ink
`#17243b`, secondary text `#596780`, action blue `#315cdf`, and warning amber
`#8a5400`. Evidence states always have text; color alone carries no meaning.
Typography uses native Aptos/Helvetica Neue/Arial for an ordinary desktop-tool
feel. A 14/16/20/28/40 scale separates navigation, instructions, section titles,
page titles and the primary health statement. Monospace is reserved for commands
and exact identifiers.

The six pages share a narrow navigation rail and one main work area. Overview
starts with a readable evidence statement and relevant action, followed by a
compact surface table. Activity uses rows with expandable evidence. Protection
uses a three-column comparison and one explicit change preview. Exceptions and
integrations use searchable lists with adjacent detail on wide screens. Settings
groups lifecycle, local data and support tasks by their consequences.

```
Tirith      | Observed protection / next action
Overview    | Evidence source and freshness
Activity    | --------------------------------
Protection  | Surface       State        Verify
Exceptions  | Terminal      Configured   ...
Integrations| Agent         Unknown      ...
Settings    |
```

Review against the brief: the primary statement is evidence rather than an
aggregate security score. There are no decorative attack counters, false
success placeholders, or claims that a configured hook prevented execution.
Cards are used only for parallel profile alternatives; other content remains
in readable rows. Layout changes at narrow widths preserve the same actions,
focus order and explicit state labels.

All dynamic content uses text nodes. Mutation controls create typed plans and
show operation state, conflicts and recovery. The UI does not reproduce policy
composition or trust matching and does not offer an arbitrary command runner.
This design is pending service integration and browser evidence.
