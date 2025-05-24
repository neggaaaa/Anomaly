import { useState } from "react";
import { useData } from "../../context/DataContext";

const ErrorDetailsTable = () => {
  const { data } = useData();
  const [searchTerm, setSearchTerm] = useState("");
  
  if (!data) {
    return (
      <div className="dashboard-card h-80">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-gray-300 text-lg font-semibold">Error Details</h2>
          <div className="h-8 w-32 bg-dark-700 rounded animate-pulse"></div>
        </div>
        <div className="h-60 flex items-center justify-center">
          <p className="text-gray-500">No data available</p>
        </div>
      </div>
    );
  }

  const issuesSource = data.issues_detected || data.issues;
  
  if (!issuesSource) {
    return (
      <div className="dashboard-card h-80">
        <h2 className="text-gray-300 text-lg font-semibold mb-4">Error Details</h2>
        <div className="h-60 flex items-center justify-center">
          <p className="text-gray-500">No error data found</p>
        </div>
      </div>
    );
  }

  const { Errors = [], Failures = [] } = issuesSource;
  
  const errorDetails = [
    ...Errors.map(e => ({ type: "Error", detail: e })),
    ...Failures.map(f => ({ type: "Failure", detail: f }))
  ];
  
  const filteredErrors = searchTerm 
    ? errorDetails.filter(item => 
        item.detail.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.type.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : errorDetails;

  return (
    <div className="dashboard-card h-80">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-gray-300 text-lg font-semibold">Error Details</h2>
        <div className="relative">
          <input
            type="text"
            className="bg-dark-700 text-dark-200 rounded py-1 px-3 pl-8 text-sm focus:outline-none focus:ring-1 focus:ring-primary-500 w-48"
            placeholder="Search errors..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <div className="absolute left-2 top-2 text-dark-400">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
            </svg>
          </div>
        </div>
      </div>
      
      <div className="h-60 overflow-y-auto">
        {filteredErrors.length > 0 ? (
          <table className="min-w-full text-gray-400">
            <thead className="bg-dark-700 sticky top-0">
              <tr>
                <th className="py-2 px-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Type</th>
                <th className="py-2 px-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700">
              {filteredErrors.map((item, index) => (
                <tr 
                  key={index} 
                  className="hover:bg-dark-700 transition-colors duration-150"
                >
                  <td className="py-2 px-4">
                    <span 
                      className={`inline-block px-2 py-1 text-xs rounded-full ${
                        item.type === "Error" 
                          ? "bg-danger-500 bg-opacity-20 text-danger-400" 
                          : "bg-warning-500 bg-opacity-20 text-warning-400"
                      }`}
                    >
                      {item.type}
                    </span>
                  </td>
                  <td className="py-2 px-4 text-sm">{item.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="h-full flex items-center justify-center">
            <p className="text-gray-500">
              {searchTerm ? "No matching errors found" : "No errors detected"}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ErrorDetailsTable;