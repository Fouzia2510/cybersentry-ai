"use client";

import Link from "next/link";

export default function HomePage() {
  return (
    <main className="landing">
      <nav className="site-nav">
        <Link className="brand" href="/" aria-label="CyberSentryAI home">
          <span className="brand-mark">◈</span>
          <span>CyberSentry<span className="brand-accent">AI</span></span>
        </Link>
        <div className="nav-actions">
          <Link className="login-link" href="/login">Log in</Link>
          <Link className="nav-cta" href="/login?mode=signup">Create account <span>↗</span></Link>
        </div>
      </nav>

      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> SECURITY INTELLIGENCE <i /> DEFENSIVE SECURITY</div>
          <h1>See your website security.<br /><span>Strengthen your defenses.</span></h1>
          <p className="hero-description">Verify domain ownership, assess website security configurations and review actionable findings in one secure workspace.</p>
          <div className="hero-actions">
            <Link className="primary-cta" href="/login?mode=signup">Get started <span>→</span></Link>
            <Link className="outline-cta" href="/login">Sign in</Link>
          </div>
          <div className="trust-line"><span>✓</span> Secure account access <b /> <span>✓</span> Ownership verification <b /> <span>✓</span> Passive assessments</div>
        </div>

        <div className="hero-visual" aria-hidden="true">
          <div className="visual-orbit orbit-one" />
          <div className="visual-orbit orbit-two" />
          <div className="visual-core"><span className="core-shield">◈</span><span className="core-label">DEFENSE ACTIVE</span></div>
          <div className="signal signal-top"><span /> DOMAIN INTEGRITY <strong>MONITORED</strong></div>
          <div className="signal signal-bottom"><span /> SECURITY POSTURE <strong>IN VIEW</strong></div>
        </div>
        <div className="hero-bottom-note"><span className="pulse-dot" /> BUILT FOR CLEARER SECURITY DECISIONS</div>
      </section>

      <section className="features-section" id="features">
        <div className="section-intro"><span>THE WORKSPACE</span><h2>Security essentials, in one place.</h2><p>Practical visibility into the website security signals that matter.</p></div>
        <div className="features">
          <article className="feature-card"><div className="feature-icon">◎</div><span className="feature-index">01 / OWNERSHIP</span><h3>Domain ownership</h3><p>Connect domains and verify ownership through a DNS challenge before bringing them into your workspace.</p><div className="feature-line" /></article>
          <article className="feature-card"><div className="feature-icon">⌕</div><span className="feature-index">02 / ASSESSMENT</span><h3>Passive security checks</h3><p>Review HTTPS, security headers and certificate details through defensive, non-invasive checks.</p><div className="feature-line" /></article>
          <article className="feature-card"><div className="feature-icon">▤</div><span className="feature-index">03 / REPORTING</span><h3>Security reports</h3><p>Keep assessment findings and history together, with clear details to help guide next steps.</p><div className="feature-line" /></article>
        </div>
      </section>

      <footer><span>© 2026 CyberSentryAI</span><span>SECURE BY DESIGN <i /> BUILT FOR DEFENSE</span></footer>

      <style jsx>{`
        .landing{min-height:100vh;overflow:hidden;background:#07111f;color:#edf5ff;font-family:Arial,Helvetica,sans-serif}
        .site-nav{height:82px;padding:0 7vw;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #ffffff12;background:#081321e8;position:relative;z-index:5}
        .brand{display:flex;align-items:center;gap:11px;color:#f1f7ff;text-decoration:none;font-size:20px;font-weight:800;letter-spacing:-.6px}
        .brand-mark{width:38px;height:38px;display:grid;place-items:center;border:1px solid #39cde45c;border-radius:11px;background:linear-gradient(145deg,#153b50,#12243c);color:#68e1f0;font-size:22px;box-shadow:0 0 24px #22c8df18}
        .brand-accent{color:#59d6e8}
        .nav-actions{display:flex;align-items:center;gap:25px}
        .nav-actions a{text-decoration:none;font-size:12px;font-weight:650}
        .login-link{color:#c0cede}.nav-cta{padding:12px 17px;border:1px solid #367b9a;border-radius:8px;background:#12334a;color:#dffaff;transition:.2s}
        .nav-cta:hover{background:#194761;border-color:#55d9e9}.nav-cta span{margin-left:8px;color:#69ddec}
        .hero{position:relative;isolation:isolate;min-height:620px;padding:105px 7vw 92px;display:flex;align-items:center;background-image:linear-gradient(90deg,#07111f 0%,#07111ff5 35%,#07111f8a 67%,#07111f50 100%),linear-gradient(0deg,#07111f 0%,transparent 24%,#07111f24 100%),url('/cyber-security-network.svg');background-size:cover;background-position:center,right center}
        .hero:after{content:"";position:absolute;inset:0;z-index:-1;background:radial-gradient(ellipse at 75% 45%,#0c8eae1c,transparent 44%);pointer-events:none}
        .hero-copy{position:relative;z-index:2;width:min(760px,66%);margin-top:-5px}
        .eyebrow{display:inline-flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid #3b82934a;border-radius:30px;background:#0b2534a8;color:#8edbe7;font-size:9px;font-weight:700;letter-spacing:1.5px}
        .eyebrow-dot,.pulse-dot{width:6px;height:6px;border-radius:50%;background:#52d9e8;box-shadow:0 0 12px #52d9e8}
        .eyebrow i{width:3px;height:3px;border-radius:50%;background:#64859a}
        h1{margin:27px 0 20px;font-size:clamp(39px,5.1vw,67px);line-height:1.1;letter-spacing:-2.9px;font-weight:760}
        h1 span{color:#83d9e9}
        .hero-description{max-width:620px;margin:0;color:#a8b8ca;font-size:16px;line-height:1.8}
        .hero-actions{display:flex;align-items:center;gap:13px;margin-top:32px}
        .hero-actions a{display:inline-flex;align-items:center;justify-content:center;min-height:47px;padding:0 19px;border-radius:8px;text-decoration:none;font-size:12px;font-weight:700;transition:.2s}
        .primary-cta{background:linear-gradient(110deg,#1688b8,#286cce);color:white;box-shadow:0 8px 30px #1688b833}
        .primary-cta:hover{filter:brightness(1.15);transform:translateY(-1px)}.primary-cta span{margin-left:13px;font-size:17px}
        .outline-cta{border:1px solid #496176;background:#0b1a2bbd;color:#e3edf8}.outline-cta:hover{border-color:#68d5e6;background:#11283a}
        .trust-line{display:flex;align-items:center;flex-wrap:wrap;gap:9px;margin-top:28px;color:#8399ae;font-size:10px;letter-spacing:.15px}
        .trust-line span{color:#5bd9c5;font-weight:bold}.trust-line b{width:3px;height:3px;margin:0 5px;border-radius:50%;background:#526b80}
        .hero-visual{position:absolute;z-index:1;right:8%;top:50%;width:350px;height:350px;transform:translateY(-50%);display:grid;place-items:center;pointer-events:none}
        .visual-orbit{position:absolute;border:1px solid #52d8e52c;border-radius:50%;box-shadow:0 0 40px #28c5df0b inset}
        .orbit-one{inset:15px;transform:rotate(-22deg) scaleY(.82);border-style:dashed}.orbit-two{inset:48px;transform:rotate(38deg) scaleY(.82)}
        .visual-core{width:145px;height:145px;border:1px solid #59d7e65c;border-radius:38px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;background:linear-gradient(145deg,#153c51e8,#101d34f2);box-shadow:0 0 75px #23c9e52b,inset 0 0 28px #5be2f00b;transform:rotate(45deg)}
        .core-shield,.core-label{transform:rotate(-45deg)}.core-shield{font-size:56px;color:#70e1ee;text-shadow:0 0 25px #43d9ed88}.core-label{font-size:8px;letter-spacing:1.6px;color:#a3eaf0;font-weight:700}
        .signal{position:absolute;padding:10px 12px;border:1px solid #4a91a44a;border-radius:7px;background:#0a1b2cdd;box-shadow:0 8px 30px #0004;color:#91aabd;font-size:8px;letter-spacing:1px;white-space:nowrap}
        .signal strong{display:block;margin-top:5px;color:#66d8e6;font-size:9px}.signal span{display:inline-block;width:5px;height:5px;margin-right:6px;border-radius:50%;background:#5be0ca;box-shadow:0 0 9px #5be0ca}
        .signal-top{top:55px;right:-18px}.signal-bottom{bottom:45px;left:-22px}
        .hero-bottom-note{position:absolute;bottom:27px;left:7vw;display:flex;align-items:center;gap:10px;color:#617c91;font-size:8px;letter-spacing:1.7px}
        .features-section{padding:82px 7vw 90px;background:linear-gradient(180deg,#091522,#0a1625);border-top:1px solid #8ed9ec12}
        .section-intro{text-align:center;margin:0 auto 37px}.section-intro>span{color:#5dcfe1;font-size:9px;font-weight:700;letter-spacing:2px}.section-intro h2{margin:13px 0 9px;color:#edf5ff;font-size:clamp(25px,3vw,34px);letter-spacing:-1px}.section-intro p{margin:0;color:#8fa3b8;font-size:12px;line-height:1.7}
        .features{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:17px;max-width:1180px;margin:0 auto}
        .feature-card{position:relative;min-height:225px;overflow:hidden;padding:25px;border:1px solid #243b50;border-radius:13px;background:linear-gradient(145deg,#102236,#0c1928);box-shadow:0 16px 40px #0209144d;transition:transform .2s,border-color .2s}
        .feature-card:hover{transform:translateY(-4px);border-color:#3b8195}
        .feature-icon{width:43px;height:43px;display:grid;place-items:center;margin-bottom:21px;border:1px solid #34788c66;border-radius:11px;background:#123348;color:#68dce9;font-size:23px}
        .feature-index{color:#64869b;font-size:8px;font-weight:700;letter-spacing:1.4px}
        .feature-card h3{margin:10px 0;color:#e8f2fc;font-size:16px}.feature-card p{max-width:310px;margin:0;color:#91a5b9;font-size:11px;line-height:1.8}
        .feature-line{position:absolute;bottom:0;left:25px;width:45px;height:2px;background:linear-gradient(90deg,#43d5e8,transparent)}
        footer{min-height:70px;padding:20px 7vw;display:flex;align-items:center;justify-content:space-between;gap:15px;border-top:1px solid #ffffff12;background:#07111f;color:#73889e;font-size:9px;letter-spacing:.6px}
        footer span:last-child{display:flex;align-items:center;gap:10px}footer i{width:3px;height:3px;border-radius:50%;background:#4e8194}
        @media(max-width:900px){.hero{min-height:600px;padding-top:90px;padding-bottom:100px;background-position:58% center}.hero-copy{width:75%}.hero-visual{right:-5%;opacity:.48;transform:translateY(-50%) scale(.85)}}
        @media(max-width:650px){.site-nav{height:70px;padding:0 20px}.brand{font-size:17px}.brand-mark{width:34px;height:34px}.nav-actions{gap:13px}.nav-actions a{font-size:10px}.nav-cta{padding:10px 11px}.hero{min-height:650px;padding:75px 22px 105px;align-items:flex-start;background-position:61% center;background-image:linear-gradient(90deg,#07111ff5,#07111fce 65%,#07111f99),linear-gradient(0deg,#07111f 0%,transparent 38%),url('/cyber-security-network.svg')}.hero-copy{width:100%;margin-top:0}.eyebrow{font-size:7px;letter-spacing:1px;gap:7px}h1{font-size:clamp(36px,10vw,49px);letter-spacing:-1.8px;margin-top:25px}.hero-description{font-size:14px;max-width:480px}.hero-visual{width:260px;height:260px;top:auto;right:-22px;bottom:12px;transform:none;opacity:.25}.visual-core{width:110px;height:110px}.core-shield{font-size:43px}.signal{display:none}.hero-bottom-note{left:22px;bottom:25px;font-size:7px}.trust-line{max-width:340px;line-height:1.8}.features-section{padding:65px 20px}.features{grid-template-columns:1fr;gap:12px}.feature-card{min-height:190px;padding:22px}.feature-icon{margin-bottom:15px}.section-intro{text-align:left;margin-bottom:27px}.section-intro h2{font-size:27px}footer{padding:20px;align-items:flex-start;flex-direction:column;gap:9px}}
        @media(prefers-reduced-motion:reduce){.feature-card,.hero-actions a,.nav-cta{transition:none}}
      `}</style>
    </main>
  );
}
