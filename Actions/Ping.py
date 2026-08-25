from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

# Integration Identifier (should match your integration name in the IDE)
INTEGRATION_NAME = "Google_ADK"
SCRIPT_NAME = "Ping"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    # Initialize default states
    status = EXECUTION_STATE_COMPLETED
    output_message = "Connectivity test successful."
    result_value = True

    try:
        # 1. Extract Config Params (The credentials we are testing)
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        model_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "Model Name", default_value="gemini-3.1-flash-lite-preview")

        # 2. Initialize Manager
        manager = GoogleADKManager(
            api_key=api_key,
            model_name=model_name,
            logger=siemplify.LOGGER
        )

        # 3. Call the test_connection method
        # This performs a handshake with the ADK/Gemini
        manager.test_connection()

        siemplify.LOGGER.info("Ping: Handshake confirmed.")

    except Exception as e:
        # If any part of the connection fails, update the status and message
        output_message = f"Connectivity test failed: {str(e)}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED 

    # Final communication back to the SOAR System
    # This is what controls the 'Test' button result in the Content Hub
    siemplify.LOGGER.info(f"Ping Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()