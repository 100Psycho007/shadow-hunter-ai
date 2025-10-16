Complete Automatic MCP Tool Usage Rules
This steering file configures Kiro to automatically use ALL available MCP tools based on task context, without requiring manual prompting.

General Principle
Always use available MCP tools proactively. Don't wait for explicit instructions. Automatically leverage the right tool for each task to maintain flow and maximize productivity.

📚 Context7 - Documentation & Library Information
When to Use Automatically:
User asks about ANY library, framework, or package
Questions about APIs, SDKs, or third-party services
"How do I..." or "Show me..." questions about code
Configuration and setup questions
Best practices for specific technologies
Version-specific features or deprecations
Examples:
✅ "Create a Next.js API route" → Auto-use Context7
✅ "How does React useEffect work?" → Auto-use Context7
✅ "Setup Tailwind CSS" → Auto-use Context7
✅ "What's new in TypeScript 5?" → Auto-use Context7
✅ "Configure Supabase auth" → Auto-use Context7
Tool Names:
get-library-docs - Fetch documentation
resolve-library-id - Find correct library identifier
🌐 Chrome DevTools - Browser Automation & Testing
When to Use Automatically:
User mentions testing a website or web app
Performance analysis requests
Screenshot or visual verification needs
Debugging frontend issues
Checking how a site renders
Network request inspection
Any mention of "check this website" or "test this page"
Examples:
✅ "Check if our homepage loads fast" → Auto-use Chrome DevTools
✅ "Take a screenshot of example.com" → Auto-use Chrome DevTools
✅ "Test this URL: https://..." → Auto-use Chrome DevTools
✅ "See what network requests are made" → Auto-use Chrome DevTools
✅ "Debug why this page is slow" → Auto-use Chrome DevTools
🔍 BrightData - Web Research & Scraping
When to Use Automatically:
User asks about current/real-time information
Questions starting with "What's the current..." or "What's today's..."
Market research or competitive analysis
Product/price information from websites
News or trending topics
Data extraction from public websites
Any information that changes frequently
Examples:
✅ "What's Tesla's stock price?" → Auto-use BrightData
✅ "Find today's weather in Tokyo" → Auto-use BrightData
✅ "What are the trending topics on Twitter?" → Auto-use BrightData
✅ "Get product details from this Amazon URL" → Auto-use BrightData
✅ "What's in the news about AI today?" → Auto-use BrightData
📝 Basic Memory - Knowledge Persistence
When to Use Automatically:
User asks to "remember" something
Information that should persist across sessions
Project decisions, architecture choices, or conventions
Team preferences and standards
Any important context worth saving
When user asks "what do I know about..." or "what have we discussed..."
Examples:
✅ "Remember that we use Tailwind for styling" → Auto-use Basic Memory (write)
✅ "What did we decide about authentication?" → Auto-use Basic Memory (read)
✅ "Save these API endpoints for later" → Auto-use Basic Memory (write)
✅ "What are my project conventions?" → Auto-use Basic Memory (read)
✅ After important discussions → Auto-suggest saving to memory
Tool Names:
write_note - Create/update notes
read_note - Read existing notes
search_notes - Search knowledge base
build_context - Navigate knowledge graph
recent_activity - Find recent updates
📁 Filesystem - File Operations
When to Use Automatically:
User asks to read, create, or modify files
"Show me the code in..." questions
File structure exploration
Code review or analysis tasks
Any task requiring file system access
Examples:
✅ "Show me the main.ts file" → Auto-use Filesystem
✅ "Create a new component file" → Auto-use Filesystem
✅ "What's in the src directory?" → Auto-use Filesystem
✅ "Read the package.json" → Auto-use Filesystem
🧠 Memory Server - Knowledge Graph
When to Use Automatically:
Building connections between concepts
Storing structured information
Creating relationships between entities
Long-term project knowledge
Semantic search across stored information
Examples:
✅ "Remember the relationship between User and Profile models" → Auto-use Memory
✅ "What entities are related to authentication?" → Auto-use Memory
✅ After discussing architecture → Auto-store entities and relations
🤔 Sequential Thinking - Complex Problem Solving
When to Use Automatically:
Multi-step problems requiring planning
Architecture decisions
Complex debugging scenarios
Design discussions
Any task that benefits from breaking down into steps
Examples:
✅ "How should I architect this feature?" → Auto-use Sequential Thinking
✅ "Debug this complex issue..." → Auto-use Sequential Thinking
✅ "Plan the implementation of..." → Auto-use Sequential Thinking
🐙 GitHub - Repository Management
When to Use Automatically:
User mentions GitHub, repos, issues, PRs
Questions about repositories or code on GitHub
Creating issues or tracking bugs
Searching for code examples
Managing pull requests
Any GitHub-related task
Examples:
✅ "Create an issue for this bug" → Auto-use GitHub
✅ "Show me recent commits" → Auto-use GitHub
✅ "Search for React components on GitHub" → Auto-use GitHub
✅ "Get the README from facebook/react" → Auto-use GitHub
✅ "Create a PR for this feature" → Auto-use GitHub
✅ "List all open issues in our repo" → Auto-use GitHub
Tool Names:
create_issue - Create GitHub issues
search_repositories - Search GitHub
get_file_contents - Read files from repos
create_pull_request - Create PRs
list_commits - View commit history
📦 Git - Version Control
When to Use Automatically:
User asks about changes, commits, branches
Version control operations
Code history questions
When user mentions "commit", "branch", "merge", "diff"
After making significant changes to code
Examples:
✅ "Show me what changed" → Auto-use Git
✅ "Commit these changes" → Auto-use Git
✅ "Create a new branch for this feature" → Auto-use Git
✅ "Show git history" → Auto-use Git
✅ "What's the status of my repo?" → Auto-use Git
✅ After code changes → Suggest committing with good message
Tool Names:
git_status - Check current status
git_diff - Show changes
git_log - View history
git_commit - Commit changes
git_add - Stage files
git_branch - Branch operations
⚡ Everything Search - Fast File Finding (Windows)
When to Use Automatically:
User asks to find files across entire system
"Where is..." or "Find all..." questions
Searching for specific file types
Locating config files or resources
Any file search beyond current project
Examples:
✅ "Find all .tsx files on my computer" → Auto-use Everything
✅ "Where is my config file?" → Auto-use Everything
✅ "Search for images in my downloads" → Auto-use Everything
✅ "Find all package.json files" → Auto-use Everything
🔎 Brave Search - Web Search
When to Use Automatically:
User asks for current information not in training data
Research questions
Finding examples or tutorials
Technical problem solving
"How to..." questions that might benefit from web search
Examples:
✅ "What are the latest Next.js features?" → Auto-use Brave Search
✅ "Find tutorials on GraphQL subscriptions" → Auto-use Brave Search
✅ "Search for solutions to this error" → Auto-use Brave Search
✅ "What's the best practice for..." → Auto-use Brave Search
🗄️ Supabase - Cloud Database Operations
When to Use Automatically:
User mentions Supabase or database operations
Questions about tables, queries, or data
Authentication and user management (if using Supabase Auth)
Storage operations (if using Supabase Storage)
Examples:
✅ "Show me all users in Supabase" → Auto-use Supabase
✅ "Query the posts table" → Auto-use Supabase
✅ "Create a new table for..." → Auto-use Supabase
✅ "Check if user exists in database" → Auto-use Supabase
🎭 Puppeteer - Advanced Browser Automation
When to Use Automatically:
Complex web scraping needs
Form filling and interactions
Multi-step browser automation
E2E testing scenarios
When Chrome DevTools isn't powerful enough
Examples:
✅ "Fill out this form and submit" → Auto-use Puppeteer
✅ "Scrape data from this paginated site" → Auto-use Puppeteer
✅ "Test the checkout flow" → Auto-use Puppeteer
✅ "Login and extract data" → Auto-use Puppeteer
💬 Slack - Team Communication
When to Use Automatically:
User wants to send Slack messages
Checking team channels
Looking up past conversations
Notifying team members
Any Slack-related task
Examples:
✅ "Send a message to #general" → Auto-use Slack
✅ "Check recent messages in #dev" → Auto-use Slack
✅ "Notify the team about this deployment" → Auto-use Slack
✅ "Search for discussions about authentication" → Auto-use Slack
🔗 Tool Combination Strategies
Smart Chaining
Research → Code → Commit:

Context7 for docs
Filesystem to write code
Git to commit
GitHub to push
Web Research → Save:

BrightData/Brave to research
Basic Memory to save findings
Code Changes → Version Control:

Filesystem to modify files
Git to show diff
Git to commit with AI-generated message
GitHub to create PR
Bug Tracking:

Sequential Thinking to analyze problem
GitHub to create issue
Basic Memory to record solution approach
🎯 Decision Flow Chart
User Request
    ↓
About a library/API/framework?
    YES → Use Context7
    
Need current/real-time info?
    YES → Use BrightData or Brave Search
    
Browser interaction needed?
    YES → Use Chrome DevTools (simple) or Puppeteer (complex)
    
Should this be remembered?
    YES → Use Basic Memory
    
File operations needed?
    YES → Use Filesystem
    
GitHub/repo related?
    YES → Use GitHub MCP
    
Version control needed?
    YES → Use Git
    
Need to find files on system?
    YES → Use Everything Search
    
Database query (Supabase)?
    YES → Use Supabase MCP
    
Team communication?
    YES → Use Slack
    
Complex multi-step problem?
    YES → Use Sequential Thinking
🚀 Proactive Tool Usage
Be Proactive - Don't Wait for Instructions
When user says: "I'm building a Next.js app with Supabase auth"

Kiro should automatically:

✅ Use Context7 → Get Next.js docs
✅ Use Context7 → Get Supabase auth docs
✅ Use Supabase MCP → Check database setup
✅ Use Basic Memory → Save architecture decisions
✅ Provide complete implementation
When user says: "Check if my website is performing well"

Kiro should automatically:

✅ Use Chrome DevTools → Run performance audit
✅ Generate detailed report
✅ Use Basic Memory → Save findings
✅ Provide optimization recommendations
After making code changes:

Kiro should automatically suggest:

✅ Use Git → Show diff
✅ Use Git → Commit with good message
✅ Use GitHub → Create PR (if appropriate)
⚙️ Auto-Approval Philosophy
Always Auto-Approve (Safe Operations):
✅ Reading/viewing operations
✅ Searching and querying
✅ Status checks
✅ Documentation fetching
Ask Permission For (Risky Operations):
❓ Writing/modifying files
❓ Creating commits
❓ Deleting anything
❓ Sending messages
❓ Making API changes
🎨 Vibe Coder Special Rules
Maintain Flow - Never Break It
Auto-use tools without asking when safe
Chain tools intelligently
Anticipate needs before user asks
Suggest next steps proactively
Smart Context Awareness
If user is in a GitHub discussion → Prioritize GitHub MCP
If user is writing code → Prioritize Context7 + Filesystem
If user is debugging → Prioritize Chrome DevTools + Sequential Thinking
If user is researching → Prioritize BrightData/Brave + Basic Memory
📊 Priority Matrix
High Priority (Use First):

Context7 - Documentation (use for any code question)
Git - Version control (use for any file changes)
GitHub - Repo management (use for any GitHub mention)
Filesystem - File operations (use for any file access)
Medium Priority (Use When Relevant): 5. Chrome DevTools - Browser testing 6. BrightData/Brave - Web research 7. Basic Memory - Knowledge storage 8. Supabase - Database operations

Low Priority (Use When Specifically Needed): 9. Puppeteer - Complex automation 10. Slack - Team communication 11. Everything Search - System-wide file search 12. Sequential Thinking - Complex problems

🔥 The Vibe Coder Workflow
Perfect Flow Example:

User: "I want to add authentication to my app"
Kiro automatically:
🔍 Use Context7 → Get auth library docs
🗄️ Use Supabase → Check current DB setup
📝 Use Filesystem → Read current auth files
💭 Use Sequential Thinking → Plan implementation
📝 Use Filesystem → Create/update files
📦 Use Git → Commit changes
💾 Use Basic Memory → Save auth approach
🐙 Use GitHub → Suggest creating PR
Result: Complete feature, properly committed, documented in memory, ready to push
All without user saying "use X tool" once. Pure vibe. 🎨✨

🎯 Success Metrics
You know the steering is working when:

✅ No need to say "use context7" anymore
✅ Tools activate automatically based on context
✅ Workflow feels seamless and natural
✅ No context switching
✅ AI anticipates your needs
✅ Everything is documented and committed properly
💡 Final Reminders
Trust the tools - Let them work automatically
Review periodically - Check what tools are being used
Adjust as needed - Update this steering file based on your workflow
Stay in flow - Don't overthink, just vibe code
The goal: Pure creation without friction. 🚀

