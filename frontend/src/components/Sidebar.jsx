import { useState } from 'react';
import FileUpload from './FileUpload';

const DashboardIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
    <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" />
  </svg>
);

const UploadIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z" clipRule="evenodd" />
  </svg>
);

const FAQIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
  </svg>
);

const ChevronLeftIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
  </svg>
);

const ChevronRightIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
  </svg>
);

const Sidebar = ({ isOpen, toggleSidebar }) => {
  const [showFAQ, setShowFAQ] = useState(false);

  return (
    <div className={`${isOpen ? 'w-64' : 'w-20'} bg-dark-800 border-r border-dark-700 transition-all duration-300 ease-in-out flex flex-col`}>
      <div className="h-16 flex items-center justify-between px-4 border-b border-dark-700">
        {isOpen ? (
          <div className="text-xl font-bold text-primary-500">SecDashboard</div>
        ) : (
          <div className="text-xl font-bold text-primary-500 mx-auto">SD</div>
        )}
        <button 
          onClick={toggleSidebar}
          className="p-1 rounded-md text-dark-400 hover:bg-dark-700 hover:text-white focus:outline-none"
        >
          {isOpen ? <ChevronLeftIcon /> : <ChevronRightIcon />}
        </button>
      </div>

      <nav className="flex-1 space-y-1 py-4 px-2">
        <button className="bg-primary-700 text-white group flex items-center px-2 py-2 text-sm font-medium rounded-md w-full">
          <div className="mr-3 flex-shrink-0"><DashboardIcon /></div>
          {isOpen && <span>Dashboard</span>}
        </button>

        <div className="relative">
          <label 
            className="text-dark-300 hover:bg-dark-700 hover:text-white group flex items-center px-2 py-2 text-sm font-medium rounded-md w-full cursor-pointer"
            htmlFor="file-upload"
          >
            <div className="mr-3 flex-shrink-0"><UploadIcon /></div>
            {isOpen && <FileUpload text={"Upload File"}/>}
          </label>
         <FileUpload/>
        </div>

        <button 
          onClick={() => setShowFAQ(!showFAQ)}
          className="text-dark-300 hover:bg-dark-700 hover:text-white group flex items-center px-2 py-2 text-sm font-medium rounded-md w-full"
        >
          <div className="mr-3 flex-shrink-0"><FAQIcon /></div>
          {isOpen && <span>FAQ</span>}
        </button>
      </nav>

      {isOpen && showFAQ && (
        <div className="p-4 border-t border-dark-700 bg-dark-700 text-sm">
          <h3 className="font-semibold text-white mb-2">Frequently Asked Questions</h3>
          <ul className="space-y-2 text-dark-300">
            <li>• How to upload logs?</li>
            <li>• Supported file formats?</li>
            <li>• How to read the heatmap?</li>
            <li>• What are anomalies?</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default Sidebar;