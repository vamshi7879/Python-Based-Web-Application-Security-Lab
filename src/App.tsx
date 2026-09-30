import { useState } from 'react'
import './App.css'

function App() {
  const [count, setCount] = useState(0)

  return (
    <div className="container">
      <header>
        <h1>Python Security Lab</h1>
        <p>AST-based Static Security Scanner</p>
      </header>
      <main>
        <section className="hero">
          <h2>Detect Security Weaknesses</h2>
          <p>Comprehensive security analysis for Python applications</p>
          <button onClick={() => setCount((count) => count + 1)}>
            Count: {count}
          </button>
        </section>
        <section className="features">
          <div className="feature">
            <h3>Static Analysis</h3>
            <p>Deep AST-based code analysis</p>
          </div>
          <div className="feature">
            <h3>Risk-Based Guidance</h3>
            <p>Prioritized remediation recommendations</p>
          </div>
          <div className="feature">
            <h3>Security Focused</h3>
            <p>Detect secure-coding weaknesses</p>
          </div>
        </section>
      </main>
      <footer>
        <p>&copy; 2024 Python Security Lab. All rights reserved.</p>
      </footer>
    </div>
  )
}

export default App
