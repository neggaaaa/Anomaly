const BACKEND_URL = "https://anomaly-api.onrender.com";

export const uploadFile = async (file) => {
  const formData = new FormData();
  formData.append("file", file);
  
  try {
    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: "POST",
      body: formData,
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error("Upload error:", error);
    throw new Error("Ошибка при загрузке файла: " + error.message);
  }
};

export const getOverviewData = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/overview`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error("Overview data error:", error);
    throw new Error("Ошибка при получении данных обзора: " + error.message);
  }
};

export const getAnomalyData = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/anomalies`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error("Anomaly data error:", error);
    throw new Error("Ошибка при получении данных аномалий: " + error.message);
  }
};
