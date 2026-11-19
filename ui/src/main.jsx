import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { CaseList } from './CaseList.jsx'
import { CaseView } from './CaseView.jsx'
import './styles.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<CaseList />} />
        <Route path="/case/:caseId" element={<CaseView />} />
        <Route path="*" element={<CaseList />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
