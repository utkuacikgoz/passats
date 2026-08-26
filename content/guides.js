'use strict';

// Content for the guide pages. Each entry renders to views/guides/<slug>.html
// via scripts/build-guides.js, so the shell — nav, footer, canonical, Article
// schema, the CTA — is defined once and cannot drift between pages.
//
// These exist to rank and to be worth linking to. A page that only sells is a
// page nobody cites, so each one answers its question properly and says where
// the honest limits are, including ours.

module.exports = [
  {
    slug: 'resume-keywords',
    title: 'Resume Keywords That Actually Matter, By Role',
    description: 'The terms applicant tracking systems look for in engineering, product, data, marketing and finance resumes, and how to use them without keyword stuffing.',
    h1: 'Resume Keywords That Actually Matter',
    standfirst: 'Matching is usually literal. That single fact explains most of what follows, and most of why generic keyword advice fails.',
    sections: [
      { h2: 'Why the exact word matters', body: [
        'Most applicant tracking systems match strings, not meaning. If a posting asks for <strong>CI/CD</strong> and your resume says "continuous integration", a literal matcher scores that as a miss. It does not know they are the same thing.',
        'The fix is not to write both everywhere. It is to write both <em>once</em>, in the place a reader would expect: <code>CI/CD (continuous integration and delivery)</code>. You get the exact-match credit and a human still reads a normal sentence.',
        'This is also why copying a keyword list wholesale does not work. The list below is a starting point for what is standard in a role. The posting in front of you is the actual answer.',
      ]},
      { h2: 'Software engineering', body: [
        'TypeScript, React, Vue, Angular, Node.js, Python, Go, CI/CD, Docker, Kubernetes, AWS, GCP, REST API, GraphQL, unit testing, integration testing, Git, Agile, code review, microservices, PostgreSQL, Redis.',
        'What separates a strong engineering resume is rarely the stack list. It is whether the bullets underneath show scale: how much traffic, how much data, how many services, how long the thing has run in production.',
      ]},
      { h2: 'Product management', body: [
        'Product roadmap, OKR, A/B testing, stakeholder management, go-to-market, sprint planning, KPI, user story, discovery, prioritisation, backlog, user research, product analytics, north star metric, requirements, cross-functional.',
        'Product resumes fail most often on outcome, not vocabulary. "Owned the roadmap" is a job description. "Cut onboarding drop-off from 46% to 31% over two quarters" is a candidate.',
      ]},
      { h2: 'Data and analytics', body: [
        'SQL, Python, R, Tableau, Power BI, Looker, A/B testing, ETL, dbt, statistical analysis, regression, dashboard, pandas, data modelling, experimentation, cohort analysis, Snowflake, BigQuery.',
        'Name the tools you would be comfortable being tested on. Data roles interview on exactly the terms listed in the resume more often than most.',
      ]},
      { h2: 'Marketing and growth', body: [
        'SEO, SEM, conversion rate, Google Analytics, CRM, HubSpot, campaign management, A/B testing, funnel, CAC, LTV, attribution, email marketing, content strategy, paid social, lifecycle, retention.',
        'Marketing resumes carry the most unquantified language of any discipline. Every claim here has a number attached to it somewhere in your analytics. Go and get it.',
      ]},
      { h2: 'Finance and operations', body: [
        'Financial modelling, Excel, P&amp;L, variance analysis, FP&amp;A, IFRS, GAAP, forecasting, budgeting, Power BI, reconciliation, month-end close, audit, cash flow, SQL, NetSuite, SAP.',
        'Name the systems. A finance resume that says "ERP experience" without naming which one reads as evasive to anyone who has run that stack.',
      ]},
      { h2: 'How to place them', body: [
        'A real Skills section with twelve to twenty terms that are genuinely yours. Not every technology you have ever opened.',
        'Then the same terms again, naturally, inside the bullets where you actually used them. A term that appears in a Skills list and nowhere else reads as thin to a human even when it scores fine.',
        'Never in white text, never in a hidden block, never in the document properties. It is trivially visible to anyone who selects the page, and it ends the application on integrity rather than fit.',
      ]},
    ],
  },

  {
    slug: 'ats-score-guide',
    title: 'What Your ATS Score Actually Means',
    description: 'How to read an ATS compatibility score, what each band implies, how the four components are weighted, and what a score cannot tell you.',
    h1: 'What Your ATS Score Actually Means',
    standfirst: 'A score is a diagnostic, not a verdict. Its only real job is telling you which part to fix first.',
    sections: [
      { h2: 'The bands', body: [
        '<strong>Below 45.</strong> Something structural is wrong, not cosmetic. Usually a missing Skills section, a layout the parser cannot read in order, or text that is not really text. Fix the structure before touching wording.',
        '<strong>45 to 60.</strong> Readable, but it is not competing. Typically thin keyword overlap and bullets that describe duties rather than outcomes. This is the band where the most improvement is available per hour spent.',
        '<strong>61 to 75.</strong> A solid resume that loses to better-matched ones. The work here is targeting: mirroring the specific posting rather than sending one generic document everywhere.',
        '<strong>76 to 85.</strong> Strong. Remaining gains are narrow and role-specific. Worth tailoring per application rather than rewriting.',
        '<strong>Above 85.</strong> The resume is not what is holding you back. Look at where you are applying and who is referring you.',
      ]},
      { h2: 'How the four parts are weighted', body: [
        'A composite score hides which part is dragging. PassATS weights ours like this, and most tools are directionally similar:',
        '<strong>Keywords, 35%.</strong> The heaviest single component, and the most fixable in an afternoon.',
        '<strong>Formatting, 30%.</strong> Whether the structure survives extraction: standard headings, readable order, consistent dates.',
        '<strong>Contact information, 20%.</strong> Present, parseable, and not stranded in a header region some parsers skip.',
        '<strong>Readability, 15%.</strong> Sentence length, bullet density, whether a human can scan it in twenty seconds.',
        'The practical consequence: a 68 driven by a 40 on keywords is a different job from a 68 driven by a 40 on formatting. Always look at the components, never just the total.',
      ]},
      { h2: 'What a score cannot tell you', body: [
        'It cannot tell you whether you are qualified. It measures how legible your case is, not how strong it is.',
        'It cannot predict a specific employer. Systems differ, configurations differ, and the same resume scores differently across them.',
        'It cannot see your rendered page. Every checker reads extracted text, so none can reliably tell you whether your two columns interleave or whether something is hidden. Open your PDF and try to select a sentence. That ten-second test catches what software cannot.',
      ]},
    ],
  },

  {
    slug: 'resume-file-format',
    title: 'PDF or DOCX? Which Resume File Format to Send',
    description: 'When PDF wins, when DOCX wins, why image-based PDFs fail completely, and which formats to never send.',
    h1: 'PDF or DOCX?',
    standfirst: 'The short answer is PDF, unless the application form asks for something else. The long answer is that the format matters far less than whether the text inside it is real.',
    sections: [
      { h2: 'The one test that matters', body: [
        'Open your resume. Try to select a sentence with your cursor and copy it. Paste it somewhere.',
        'If nothing highlights, or you paste nothing, your resume contains no text at all. It is a picture of a resume. No parser can read it, no keyword can match, and no score is meaningful. This happens to anyone who scanned a printout, exported from a design tool at the wrong setting, or saved from a screenshot.',
        'This is the single most catastrophic and most invisible problem in resume formatting, and it takes ten seconds to rule out.',
      ]},
      { h2: 'When PDF wins', body: [
        'It preserves your layout exactly, so what a human opens is what you designed. Modern parsers handle it consistently. It cannot be accidentally edited in transit.',
        'Send PDF by default. Export from your editor rather than printing to PDF where you have the choice, since the export path more reliably keeps the text layer intact.',
      ]},
      { h2: 'When DOCX wins', body: [
        'When the application form explicitly asks for it. Some older systems and some recruitment agencies still prefer it, and a few will reject a PDF outright.',
        'Recruiters who reformat resumes onto their own letterhead also prefer DOCX, because it saves them retyping. If you are working through an agency, ask.',
      ]},
      { h2: 'What not to send', body: [
        '<strong>.pages</strong> — most systems cannot open it at all.',
        '<strong>.odt</strong> — inconsistent support, no upside.',
        '<strong>.txt</strong> — parses perfectly and looks like you gave up.',
        '<strong>A link to a Google Doc</strong> — permissions fail, and it puts an extra step between a recruiter and your experience.',
        '<strong>An encrypted or password-protected PDF</strong> — cannot be parsed at all. If you protected the file at any point, export a clean copy.',
      ]},
      { h2: 'Name the file properly', body: [
        '<code>Jane-Okafor-Product-Manager.pdf</code>. Not <code>resume-final-v4-USE-THIS-ONE.pdf</code>.',
        'It costs nothing, it is the first thing a human sees, and it is what your file will be called in a folder of four hundred others.',
      ]},
    ],
  },

  {
    slug: 'ats-parsing-errors',
    title: 'Why Your Resume Does Not Parse',
    description: 'The specific ways resume layouts break applicant tracking systems, what the machine sees instead, and how to detect each one yourself.',
    h1: 'Why Your Resume Does Not Parse',
    standfirst: 'Parsing failures are not random. There are about six of them, they are all visual choices, and each one has a tell you can check in under a minute.',
    sections: [
      { h2: 'Two columns', body: [
        '<strong>What you see:</strong> skills down the left, experience down the right.',
        '<strong>What the parser sees:</strong> text read left to right across both columns, so your job titles interleave with your skill list. "Senior Engineer Python 2021 to 2024 SQL Led migration Docker".',
        '<strong>How to check:</strong> select all, copy, paste into a plain text editor. If the result is scrambled, so is the machine\'s copy.',
      ]},
      { h2: 'Tables and text boxes', body: [
        '<strong>What you see:</strong> a tidy grid of skills, or a highlighted sidebar.',
        '<strong>What the parser sees:</strong> cell fragments with no reading order. Text boxes are worse — many parsers skip them entirely, so that content simply does not exist.',
        '<strong>How to check:</strong> the same copy-paste test. Missing content is the tell.',
      ]},
      { h2: 'Contact details in the header or footer', body: [
        '<strong>What you see:</strong> your name and email neatly at the top of every page.',
        '<strong>What the parser sees:</strong> in some systems, nothing. Header and footer regions are commonly ignored.',
        '<strong>The consequence:</strong> you can be the strongest candidate in the pile and still be unreachable. Put contact details in the body of the first page.',
      ]},
      { h2: 'Creative section headings', body: [
        '<strong>What you see:</strong> "Where I Have Made An Impact".',
        '<strong>What the parser sees:</strong> an unclassifiable block. It looks for the words it knows — Experience, Education, Skills, Summary — and assigns everything underneath to that section. An unrecognised heading means the content beneath it never gets categorised.',
        'This is the most common self-inflicted wound in resume design, because it feels like personality rather than a technical choice.',
      ]},
      { h2: 'Words inside graphics', body: [
        '<strong>What you see:</strong> a skills wheel, a proficiency chart, a logo containing your name.',
        '<strong>What the parser sees:</strong> nothing. An image is not text.',
        'If a piece of information matters, it has to exist as selectable characters somewhere on the page.',
      ]},
      { h2: 'Inconsistent dates', body: [
        '<strong>What you see:</strong> <code>Jan 2023</code> in one role and <code>01/2023</code> in another.',
        '<strong>What the parser sees:</strong> a history it cannot reliably order, and sometimes a gap that is not really there.',
        'Pick one format and use it everywhere.',
      ]},
    ],
  },

  {
    slug: 'ats-resume-template',
    title: 'An ATS-Friendly Resume Structure You Can Copy',
    description: 'The section order applicant tracking systems expect, what belongs in each one, and a plain structure you can rebuild your resume around.',
    h1: 'An ATS-Friendly Resume Structure',
    standfirst: 'Not a downloadable file. A structure, in the order parsers expect it, that you can rebuild your own resume around in about twenty minutes.',
    sections: [
      { h2: 'The order', body: [
        'Contact details, then Summary, then Skills, then Experience, then Education. Anything else after that.',
        'Skills sits high deliberately. It is the densest keyword block on the page and the section most likely to be read before a human decides whether to continue.',
        'Experience before Education unless you graduated within the last year or the role explicitly asks for academic background.',
      ]},
      { h2: 'Contact details', body: [
        'Full name, city and country, email, phone, one URL. In the body of the page, not in the header region.',
        'Skip your full street address. It is a privacy exposure with no upside, and nobody is posting you anything.',
      ]},
      { h2: 'Summary', body: [
        'Three lines. Your role, your years of relevant experience stated as a number, and the one thing you want remembered.',
        'A summary that could sit on anyone else\'s resume is worse than no summary. If it does not name something specific, cut it and give the space to Experience.',
      ]},
      { h2: 'Skills', body: [
        'Twelve to twenty terms, comma separated, in plain text. Not a table, not a grid, not a set of rating bars.',
        'Group them if it helps a reader: languages, then frameworks, then tools. Keep the grouping labels short and ordinary.',
      ]},
      { h2: 'Experience', body: [
        'For each role: job title, company, dates in one consistent format. Then three to five bullets.',
        'Each bullet: what you did, and what changed because of it. "Migrated 4TB of customer data across 12 services with no downtime" rather than "Responsible for the data migration project".',
        'Lead with the verb. Put a number in most of them. If you cannot find a number, name the scale — team size, user count, budget, how many countries.',
      ]},
      { h2: 'Education', body: [
        'Degree, institution, year. That is usually enough.',
        'Add coursework or a thesis only when you are early enough in your career that it is the strongest evidence you have.',
      ]},
      { h2: 'What to leave out', body: [
        'A photograph, unless you are applying somewhere it is the local convention. In many markets it introduces bias risk and some systems strip it anyway.',
        'Date of birth, marital status, nationality. Same reason.',
        '"References available on request." Everyone knows. It is four words of nothing.',
        'A skills rating out of five. Nobody agrees what four out of five means, including you.',
      ]},
    ],
  },
];
