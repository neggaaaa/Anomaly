import { useData } from "../context/DataContext";
import AnomalyChart from "../components/charts/AnomalyChart";
import HeatmapChart from "../components/charts/HeatmapChart";
import ErrorDistributionChart from "../components/charts/ErrorDistributionChart";
import StatsCards from "../components/cards/StatsCards";
import ErrorDetailsTable from "../components/tables/ErrorDetailsTable";
import TopPortsTable from "../components/tables/TopPortsTable";
import RecommendationsPanel from "../components/panels/RecommendationsPanel";
import FileUpload from "../components/FileUpload";
import AnomalyDetectionPlot from "../components/charts/AnomalyDetectionPlot";


const Dashboard = () => {
  const { data, loading, error } = useData();

  return (
    <div className="container mx-auto">
      {loading ? (
        <div className="flex items-center justify-center h-40 mb-4">
          <div className="inline-flex items-center px-4 py-2 border border-transparent text-base leading-6 font-medium rounded-md text-white bg-primary-700 animate-pulse">
            <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Loading data...
          </div>
        </div>
      ) : error ? (
        <div className="bg-danger-500 bg-opacity-20 border border-danger-500 text-danger-400 px-4 py-3 rounded-md mb-4">
          <div className="flex items-center">
            <svg className="h-5 w-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <p>{error}</p>
          </div>
        </div>
      ) : !data ? (
  <div className="bg-dark-800 px-6 py-16 rounded-lg border border-dark-700 shadow-lg text-center mb-6">
    <h3 className="text-xl font-semibold text-gray-300 mb-2">Welcome to Security Dashboard</h3>
    <p className="text-dark-400 mb-6">Upload a log file to analyze security data and detect anomalies</p>
    <div className="animate-pulse-slow text-primary-500">
      <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z" clipRule="evenodd" />
      </svg>
    </div>
    <p className="text-dark-400 mt-4">Click the upload button to start</p>
    <div className="flex justify-center mb-4 mt-4">
      <div className="w-[150px] pb-1 bg-blue-600 hover:bg-blue-800 rounded-lg shadow-md transition duration-300">
        <FileUpload text={"Upload File"} />
      </div>
    </div>
  </div>
) : (
        <>
          <div className="mb-6">
            <StatsCards />
          </div>
          <div className="mb-6">
             <AnomalyDetectionPlot />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <AnomalyChart />
            <HeatmapChart />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <ErrorDistributionChart />
            <RecommendationsPanel />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <TopPortsTable />
            <ErrorDetailsTable />
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;