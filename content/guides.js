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

  {
    slug: 'resume-summary-examples',
    title: 'How to Write a Resume Summary That Is Not Filler',
    description: 'What a resume summary is for, the three lines it should contain, and why most of them are deleted without being read.',
    h1: 'How to Write a Resume Summary',
    standfirst: 'Most summaries say nothing. A good one earns the next thirty seconds of attention, and it does that with specifics rather than adjectives.',
    sections: [
      { h2: 'Three lines, and what goes in each', body: [
        '<strong>Line one: what you are and for how long.</strong> "Product manager, eight years, consumer fintech." Not "results-driven professional with a passion for excellence."',
        '<strong>Line two: the strongest evidence you have.</strong> One outcome with a number in it. The thing you would lead with if you had ten seconds in a lift.',
        '<strong>Line three: what you are looking for, only if it is not obvious.</strong> Skip it when you are applying for the same role you already do.',
      ]},
      { h2: 'The adjective test', body: [
        'Read your summary and delete every adjective. Motivated, passionate, dynamic, detail-oriented, results-driven, hard-working.',
        'If what remains still says something, the adjectives were decoration and you can leave them out. If nothing remains, the summary was never saying anything, and the space belongs to your Experience section instead.',
      ]},
      { h2: 'Two versions of the same person', body: [
        '<strong>Before:</strong> "Results-driven marketing professional with a proven track record of delivering impactful campaigns in fast-paced environments."',
        '<strong>After:</strong> "Growth marketer, six years, B2B SaaS. Took paid acquisition from £180 to £62 CAC across four quarters at a Series B. Looking for a senior role with budget ownership."',
        'The second is shorter in adjectives and longer in evidence. It also gives a recruiter three things to ask about, which is the actual job of a summary.',
      ]},
      { h2: 'When to leave it out entirely', body: [
        'If you are early in your career and the strongest thing about you is your most recent role, lead with the role.',
        'A summary that repeats the job titles directly beneath it costs you five lines at the top of the page, which is the most valuable space you have.',
      ]},
      { h2: 'What it does for parsing', body: [
        'A summary is a dense, natural place for the terms a role expects, so it carries real keyword weight in most scoring.',
        'That is a reason to write it well, not a reason to stuff it. A list of technologies with no sentence around them reads as a Skills section in the wrong place, and a human will treat it as one.',
      ]},
    ],
  },

  {
    slug: 'tailor-resume-to-job-description',
    title: 'How to Tailor a Resume to a Job Description',
    description: 'A repeatable twenty-minute method for matching a resume to a specific posting without rewriting it from scratch each time.',
    h1: 'How to Tailor a Resume to a Job Description',
    standfirst: 'Sending the same document to forty postings is why the replies stop. Tailoring does not mean rewriting, and it should take about twenty minutes.',
    sections: [
      { h2: 'Start by reading the posting as a checklist', body: [
        'Copy the posting into a plain document. Highlight every hard requirement: named tools, years of experience, certifications, a degree if one is genuinely required.',
        'Those are the terms that get matched literally. Everything else in the posting is atmosphere.',
      ]},
      { h2: 'Sort them into three piles', body: [
        '<strong>Have it and said it.</strong> Nothing to do.',
        '<strong>Have it and did not say it.</strong> This is where nearly all your gain is. You know the tool, you used it for two years, and it appears nowhere on the page. Add it, in the role where you actually used it.',
        '<strong>Do not have it.</strong> Leave it alone. Do not claim it, do not pad around it. If it is a hard requirement you genuinely lack, the honest read is that this posting is a poor use of your twenty minutes.',
      ]},
      { h2: 'Rewrite three bullets, not the whole thing', body: [
        'Pick the three bullets closest to what the posting emphasises and rewrite those to use its language, where the language is true of what you did.',
        'A posting that keeps saying "experimentation" while your bullet says "ran A/B tests" is a match a human sees and a matcher misses. Say both.',
      ]},
      { h2: 'Reorder before you rewrite', body: [
        'Within a role, bullets do not have to stay in the order you first wrote them. Move the most relevant one to the top.',
        'Same content, better first impression, and it costs thirty seconds.',
      ]},
      { h2: 'What not to do', body: [
        'Do not paste the posting into your resume in white text. It is visible to anyone who selects the page, and it ends the application on integrity rather than fit.',
        'Do not invent a number to match a claim. Made-up metrics fall apart in the first interview, which is a worse outcome than not getting one.',
        'Do not tailor the summary and forget the Skills section. They are the two densest places, and a mismatch between them reads as carelessness.',
      ]},
    ],
  },

  {
    slug: 'resume-length',
    title: 'How Long Should a Resume Be?',
    description: 'When one page is right, when two is expected, and why the page count matters far less than what is in the first third.',
    h1: 'How Long Should a Resume Be?',
    standfirst: 'One page is advice, not a rule. The real constraint is that almost nobody reads past the first third, whatever the length.',
    sections: [
      { h2: 'The short answer', body: [
        '<strong>Under five years of experience:</strong> one page. You will not have enough evidence to fill two without padding, and padding is visible.',
        '<strong>Five to fifteen years:</strong> two pages is normal and expected. Compressing fifteen years onto one page means cutting the evidence that makes you credible.',
        '<strong>Academic, research or senior technical:</strong> longer is conventional, and a publication list is not a resume anyway.',
      ]},
      { h2: 'Why the rule exists', body: [
        'The one-page rule is a proxy for a real problem: most resumes are too long because they list duties rather than outcomes.',
        'Cutting to one page usually forces the right edit. That is why the advice works even though the rule itself is arbitrary.',
      ]},
      { h2: 'What actually gets read', body: [
        'The top third of the first page. Your name, your summary, and your most recent role.',
        'This is why page count matters less than order. A strong second page nobody reaches is worth less than one line moved higher.',
      ]},
      { h2: 'What to cut first', body: [
        'Roles more than fifteen years old, unless they are the reason you are qualified. A single line each is enough.',
        'Duties that any holder of that job title would have had.',
        '"References available on request." Everyone knows.',
        'A skills rating out of five. Nobody agrees what four means, including you.',
        'Anything you would not want to be asked about in detail.',
      ]},
      { h2: 'What length does to parsing', body: [
        'Length itself is not scored. A parser reads two pages as happily as one.',
        'What does hurt is the compression people apply to hit one page: shrinking margins to nothing, dropping to eight point type, or moving content into a sidebar to save vertical space. That last one is a genuine parsing failure, and it is caused by the page count rule rather than by the length.',
      ]},
    ],
  },

  {
    slug: 'chatgpt-resume-ats-check',
    title: 'Can ChatGPT or Claude Check Your Resume for ATS?',
    description: 'What a chat assistant can genuinely do for your resume, what it structurally cannot see, and how to tell which kind of problem you have.',
    h1: 'Can ChatGPT or Claude Check Your Resume for ATS?',
    standfirst: 'Partly, and the part it cannot do is not about how clever the model is. It is about what the model is handed. We sell a paid checker, so the case for using a free chat assistant instead is set out first and in full.',
    sections: [
      { h2: 'The short answer', body: [
        'A chat assistant is <strong>good at your writing</strong> and <strong>blind to your file</strong>.',
        'Paste your resume into ChatGPT or Claude and ask it to sharpen your bullets, and you will get useful work back: weak verbs replaced, vague claims challenged, a summary rewritten to lead with the thing that matters. That is a genuine editing job and it costs nothing.',
        'Ask the same assistant whether your resume will parse, and it is answering about text you gave it. It never opened your document. Those are different questions, and only one of them is about the file you are actually sending.',
      ]},
      { h2: 'What it does well, and you should just use it for', body: [
        '<strong>Rewriting bullets.</strong> Paste one bullet, give it the outcome, and ask for three versions that lead with the result. This works well and it is free.',
        '<strong>Finding the vague sentence.</strong> Ask it which bullets say nothing measurable. It is unsentimental about your prose in a way that is hard to be about your own.',
        '<strong>Comparing against a posting.</strong> Paste the job description and your resume text, and ask which requirements are unaddressed. For content gaps, this is real analysis.',
        '<strong>Drafting a summary.</strong> Give it your last three roles and ask for a four-line profile. Then cut a line, because it will write five.',
        'If your problem is that your resume reads weakly, stop here. A chat assistant will fix that, and you do not need us for it.',
      ]},
      { h2: 'What it structurally cannot do', body: [
        'When you paste, you paste <strong>the text you could select</strong>. That is not the same object an applicant tracking system receives, and the gap is where most parsing failures live.',
        '<strong>It cannot see what failed to extract.</strong> Contact details placed in a page header are a common casualty: they look fine on screen and can be absent from the extracted text entirely. Pasting cannot reveal this, because you paste what you can see, and the missing thing is by definition not there to notice.',
        '<strong>It cannot see reading order.</strong> Content arranged in separate places on the page can come out interleaved on a single line, in an order no reader would choose. Your pasted version has none of that, because copying often tidies it up.',
        '<strong>It cannot see text you cannot see.</strong> Some resumes carry keywords set in 2pt type, or white on a white background, added by a template or a "free ATS optimiser" without telling the candidate. You cannot paste text you do not know is there.',
        'None of this improves when the model does. A better model given the same pasted text still has not seen the file.',
      ]},
      { h2: 'How to tell which problem you have', body: [
        'Open your resume, select all, copy, and paste it into a plain text editor. Not a document editor: something with no formatting at all.',
        'Now read what appears. Is your email address there? Your phone number? Do the sections come out in the order you wrote them, or has a sidebar landed in the middle of a job? Is anything present that you did not intend to write?',
        'If that text reads cleanly and your problem is that the writing is flat, a chat assistant is the right tool and it is free.',
        'If things are missing or scrambled, no amount of rewriting will help, because the words you are improving are not the words being read. That is a file problem, and it needs something that opens the file.',
        'Our <a href="/ats-parse-preview">free parse preview</a> does that step properly and costs nothing. So does the copy-paste test above, which is why we just told you how to do it.',
      ]},
      { h2: 'The honest comparison', body: [
        '<strong>Use a chat assistant when</strong> your content needs work: weak bullets, no metrics, a summary that states your job title back at you. It is free, it is fast, and it is good at this.',
        '<strong>Use a parser-based checker when</strong> you want to know what actually comes out of your file. That is the question pasting cannot answer, and it is the one that decides whether a human ever reads your writing at all.',
        '<strong>Use both</strong> in that order, honestly. Fix the file first, because a beautifully written resume that extracts into scrambled text is a beautifully written resume nobody reads.',
        'We charge $2.99 once for the file half of that. The writing half is free and we would rather you spent nothing on it.',
      ]},
      { h2: 'One thing to avoid', body: [
        'Do not ask a chat assistant to generate a keyword block to paste into your resume. It will oblige, and the result reads as a keyword block, because that is what it is.',
        'Terms belong in the bullets where you actually did the work. A Skills list of twelve to twenty things that are genuinely yours is useful. A wall of role-adjacent nouns is visible to every human who opens the document.',
        'And never accept an offer to hide them. Hidden text is trivially visible to anyone who selects the page, and it ends an application on integrity rather than on fit.',
      ]},
    ],
  },

  {
    slug: 'ai-resume-prompts',
    title: 'AI Resume Prompts That Work, and Where They Stop',
    description: 'Specific prompts for rewriting resume bullets, summaries and role matching with a chat assistant, plus the one job no prompt can do.',
    h1: 'AI Resume Prompts That Work',
    standfirst: 'Most resume prompts fail the same way: they ask for a rewrite without giving the model anything to write about. These give it something. The last section is the job no prompt will do, whatever you type.',
    sections: [
      { h2: 'Why most prompts produce filler', body: [
        '"Make my resume better" gives the model nothing, so it returns the average of every resume it has ever seen: confident verbs, no facts, "spearheaded cross-functional initiatives".',
        'A model cannot invent what you achieved. It can only sharpen what you tell it. Every prompt below therefore makes you supply one fact first, which is the actual work.',
        'If you have no number for a bullet, go and find it before prompting. Your analytics, your old tickets, your manager\'s review. The number is the bullet.',
      ]},
      { h2: 'Rewriting a weak bullet', body: [
        'Paste one bullet at a time, not the whole resume. Whole-resume rewrites come back uniformly bland.',
        '<code>Here is one bullet from my resume: "[BULLET]". The real outcome was [NUMBER or RESULT]. Rewrite it three ways, each leading with the outcome. Keep it under 25 words. No buzzwords, no "spearheaded", no "leveraged". Do not invent any figure I have not given you.</code>',
        'That last sentence matters. Without it you will get plausible invented percentages, and a fabricated metric on a resume is a problem you carry into the interview.',
      ]},
      { h2: 'Finding your own vague lines', body: [
        '<code>Here is my experience section: [PASTE]. List every bullet that contains no measurable outcome. Do not rewrite them. Just list them, worst first, and say what fact is missing from each.</code>',
        'Asking for the diagnosis before the cure is the trick. If you ask for rewrites straight away, the model papers over the gaps with stronger verbs, and a stronger verb attached to nothing is still nothing.',
      ]},
      { h2: 'Matching a job description', body: [
        '<code>Job description: [PASTE]. My resume: [PASTE]. List the hard requirements in the posting that my resume does not address at all. Separate the ones I could address with better wording from the ones I genuinely do not have. Do not suggest I claim anything I have not done.</code>',
        'The split is the useful part. Half of what looks like a gap is usually something you did and did not mention. The other half is a real gap, and knowing which is which tells you whether to rewrite or to move on to a better-fitting posting.',
      ]},
      { h2: 'Writing the summary last', body: [
        '<code>These are my last three roles and the strongest outcome from each: [LIST]. Write a four-line professional summary that leads with total years of experience and the domain. No adjectives about my character. No "passionate", no "results-driven".</code>',
        'Write the summary after the bullets, never before. It is a distillation of the evidence, and you cannot distil what you have not written yet.',
      ]},
      { h2: 'The job no prompt can do', body: [
        'Every prompt above operates on text you pasted. That is the right tool for content, and it is free.',
        'It is not the tool for the file. When you paste, you paste what you could select, which is not what an applicant tracking system receives. Contact details can fail to survive extraction. Content from separate places on the page can come out interleaved in an order nobody would choose. Text set to be invisible does not arrive in your clipboard at all.',
        'No prompt reaches any of that, because the information is not in the conversation. It is in the document.',
        'The cheap way to check is the one we describe in <a href="/chatgpt-resume-ats-check">the chat assistant comparison</a>: copy your resume into a plain text editor and read what appears. Our <a href="/ats-parse-preview">free parse preview</a> does the same job more precisely, and also costs nothing.',
        'Fix the file first. Then use every prompt on this page, because at that point the words you sharpen are the words being read.',
      ]},
    ],
  },

  {
    slug: 'free-vs-paid-ats-checker',
    title: 'Free vs Paid ATS Checker: What the Money Actually Buys',
    description: 'What free resume checkers can and cannot do, what a paid one adds, and how to tell which you need before spending anything.',
    h1: 'Free vs Paid ATS Checker',
    standfirst: 'We sell a paid one and publish a free one, so this is written to be useful whichever you end up using. The short version: free tools answer "how does this read", paid tools answer "what exactly do I change". Most people only need the second one once.',
    sections: [
      { h2: 'What free checkers genuinely do', body: [
        'A free checker will give you a number and a short list of observations. That is worth having. If your resume scores badly across three different free tools, something structural is wrong and you have learned it for nothing.',
        'They are also fast. Thirty seconds, no decision to make. As a first sanity check before you spend anything, including on us, that is the right first move.',
      ]},
      { h2: 'Where they stop, and why', body: [
        '<strong>The advice is about resumes, not your resume.</strong> "Add more quantifiable achievements" is true of almost every resume ever written. It does not tell you that the third bullet of your Revolut role says "drove growth initiatives" and needs a number.',
        '<strong>The specifics are usually the upsell.</strong> That is not dishonest, it is the business model: the free score is the advertisement for the paid report. Worth knowing before you assume the free tier is the whole product.',
        '<strong>Many read pasted text, not your file.</strong> This is the one that matters most and the one nobody mentions. If the tool asks you to paste, it never opened your document, so it cannot tell you that your contact details failed to extract or that your content came out in an order nobody would choose.',
        '<strong>You usually pay in data.</strong> An email address at minimum, and often the resume itself, kept. Read what you are agreeing to before you upload, on any tool, ours included.',
      ]},
      { h2: 'What a paid report should add', body: [
        'If a paid tool gives you a bigger number and a longer list of generic advice, you have bought a longer advertisement. The things worth paying for are specific:',
        '<strong>Your own lines, quoted back.</strong> A fix you can act on names the section and the sentence. Anything else is a reading list.',
        '<strong>What each fix is worth.</strong> Ranked by impact, so you know which two to do tonight and which can wait.',
        '<strong>What the parser actually received.</strong> Not what the page looks like: what came out of it.',
        '<strong>Things you cannot see yourself.</strong> Text set in 2pt type or white on white, which templates and "optimisers" add without telling you, and which you cannot find by reading your own document.',
      ]},
      { h2: 'How to decide without spending anything', body: [
        'Run the free check first. Every time. If it comes back clean and your problem is that your bullets read flat, you do not have a parsing problem and no paid checker will fix your writing for you.',
        'Then do the extraction test, which is free everywhere: open your resume, select all, copy, paste into a plain text editor with no formatting. Read what appears. Missing contact details, scrambled sections, or text you did not write mean the file is failing before any human reads it.',
        'Our <a href="/ats-parse-preview">free parse preview</a> does that step more precisely and still costs nothing and takes no email. Use it, then decide.',
        'Pay only when you know what you are buying: the specific lines to change, ranked.',
      ]},
      { h2: 'When a subscription beats both', body: [
        'If you are applying at volume, tailoring for each posting over months, per-scan pricing is the wrong shape and a subscription is the rational buy. We are not the right product for that and say so in <a href="/ats-checker-comparison">the full comparison</a>.',
        'One-off pricing suits the opposite case: a handful of applications that matter, in a week that matters.',
      ]},
    ],
  },

  {
    slug: 'ats-checker-vs-chatgpt-vs-recruiter',
    title: 'ATS Checker vs ChatGPT vs a Recruiter Friend: Who Tells You What',
    description: 'Three ways to get feedback on a resume, what each one can actually see, and the order to use them in.',
    h1: 'ATS Checker vs ChatGPT vs a Recruiter Friend',
    standfirst: 'Each of these answers a different question, and using the wrong one is why resume advice so often contradicts itself. Here is what each can actually see.',
    sections: [
      { h2: 'The recruiter friend sees the pitch', body: [
        '<strong>What they see:</strong> the resume as a person reads it. Whether your seniority is legible in six seconds, whether the story of your career makes sense, whether you look like the hire.',
        '<strong>What they cannot see:</strong> what the system did with your file before it reached a human, and whether the specific terms in a specific posting are present.',
        '<strong>Best for:</strong> the judgement call. Is this a strong candidate for this job? Nothing automated answers that, and no tool ever will.',
        '<strong>The catch:</strong> they are reading your file in a viewer, the way you wrote it. That is the one version of your resume guaranteed to look correct.',
      ]},
      { h2: 'The chat assistant sees the writing', body: [
        '<strong>What it sees:</strong> the text you paste. Within that, it is genuinely good: it will find your vague bullets, rewrite them to lead with outcomes, and compare your text against a job description you also paste.',
        '<strong>What it cannot see:</strong> your file. Pasting gives it what you could select and copy, which is not the object an applicant tracking system receives. It cannot know that your phone number never made it out of the document, because the missing thing is not in what you pasted.',
        '<strong>Best for:</strong> content. Weak verbs, missing metrics, a summary that restates your job title. It is free and it is the right tool for this.',
        '<strong>The catch:</strong> ask it whether your resume will parse and it will answer confidently about text you handed it. The confidence is not evidence. We wrote up the detail in <a href="/chatgpt-resume-ats-check">can ChatGPT or Claude check your resume for ATS</a>.',
      ]},
      { h2: 'The parser sees the file', body: [
        '<strong>What it sees:</strong> what extraction produces from the document itself. Which fields survived, what order the content came out in, and text present in the file that no reader can see.',
        '<strong>What it cannot see:</strong> whether you are a good candidate. It has no view on your career, and any tool claiming otherwise from a parse is guessing.',
        '<strong>Best for:</strong> the failure nobody else can detect, because it happens before a human is involved.',
        '<strong>The catch:</strong> a clean parse is not a good resume. It only means your writing will be read. What it says is still your job, and the chat assistant is better help for that than we are.',
      ]},
      { h2: 'The order that wastes the least effort', body: [
        '<strong>First, the file.</strong> Check what extraction produces, because if your content is being mangled then every rewrite above it is wasted work. This is free: paste into a plain text editor, or use our <a href="/ats-parse-preview">parse preview</a>.',
        '<strong>Second, the writing.</strong> Now that the words will be read, make them worth reading. A chat assistant is free and effective here. There are <a href="/ai-resume-prompts">prompts that work</a>.',
        '<strong>Third, the judgement.</strong> Ask the human. By this point you are asking about fit rather than about formatting, which is the only question they are uniquely able to answer.',
        'Most people run this backwards, polishing prose inside a document that is failing to parse. That is why the advice feels like it never works.',
      ]},
    ],
  },

  {
    slug: 'ats-checker-comparison',
    title: 'Which Kind of ATS Checker Should You Use?',
    description: 'An honest comparison of the three ways resume checkers are sold, what each is really charging for, and when each one is the right choice.',
    h1: 'Which Kind of ATS Checker Should You Use?',
    standfirst: 'Resume checkers are sold three ways, and the pricing model tells you more about what you will get than the feature list does. We build one of these, so read the last section first if you would rather see the case against us.',
    sections: [
      { h2: 'Free checkers', body: [
        '<strong>What they charge:</strong> your email address, and usually your resume.',
        '<strong>What you get:</strong> a score, a few generic observations, and a prompt to upgrade before the specifics appear.',
        '<strong>When it is the right choice:</strong> when you want a rough sanity check and do not mind the follow-up email sequence. A free score does tell you whether something is badly wrong.',
        '<strong>The catch worth naming:</strong> the product is the lead. That is not dishonest, it is just what you are paying with, and it is worth knowing before you upload.',
      ]},
      { h2: 'Subscription tools', body: [
        '<strong>What they charge:</strong> a monthly fee, usually with a minimum term or an awkward cancellation.',
        '<strong>What you get:</strong> unlimited scans, and typically a suite around them — templates, tracking, sometimes a rewrite service.',
        '<strong>When it is the right choice:</strong> genuinely, when you are applying at volume over months and will tailor for each posting. If you are running twenty applications a week, per-scan pricing is worse for you and a subscription is the rational buy.',
        '<strong>The catch worth naming:</strong> most people need this for three weeks and pay for six months. Check the cancellation path before you start, not after.',
      ]},
      { h2: 'One-off reports', body: [
        '<strong>What they charge:</strong> a single fee per report.',
        '<strong>What you get:</strong> one analysis. This is what PassATS is: $2.99, no account, nothing stored, and the file discarded when the request finishes.',
        '<strong>When it is the right choice:</strong> you have one resume you care about, you want to know what is wrong with it, and you do not want a subscription or an account to cancel later.',
        '<strong>The catch worth naming:</strong> if you want to re-check after every edit, per-report pricing gets expensive fast. That is a real limitation of the model, not a detail.',
      ]},
      { h2: 'What no checker can do', body: [
        'This part is true of all three and rarely said.',
        'Every checker reads extracted text, not your rendered page. None can reliably tell you whether your two columns interleave, whether something is hidden, or whether the layout looks right. Open your file and try to select a sentence. That ten second test catches what no tool can.',
        'No checker knows how a specific employer has configured their system. Anyone promising a pass rate for a named company is guessing.',
        'And no checker can tell you whether you are qualified. It measures how legible your case is, not how strong it is.',
      ]},
      { h2: 'When not to use PassATS', body: [
        'We would rather say this than have you find out after paying.',
        '<strong>If you are going to iterate ten times.</strong> Ten reports is thirty dollars. A subscription is cheaper and better suited.',
        '<strong>If your resume is an image.</strong> Run the select-a-sentence test first. If no text highlights, no tool can read it and a report will tell you only that.',
        '<strong>If you want it rewritten for you.</strong> We tell you what to change and why. We do not write it.',
        '<strong>If you already know the problem.</strong> If you know you have no Skills section and inconsistent dates, go and fix those. You do not need us to confirm it.',
      ]},
    ],
  },
];
