##########################################################################
# appsvc
##########################################################################
set(SRC_LIST 
    main.cpp
    Application.cpp
    ApplicationShortRun.cpp
    ApplicationInitialize.cpp
    ApplicationUnInitia.cpp
    ApplicationPeriodRun.cpp
    Configuration.cpp
    RestHandler.cpp
    PrometheusRest.cpp
    AppProcess.cpp
    DockerProcess.cpp
    MonitoredProcess.cpp
    DailyLimitation.cpp
    ResourceLimitation.cpp
    ResourceCollection.cpp
    LinuxCgroup.cpp
    User.cpp
    Role.cpp
    Label.cpp
    HealthCheckTask.cpp
    PersistManager.cpp
    ConsulConnection.cpp
    ConsulEntity.cpp
    Scheduler.cpp
    TimerHandler.cpp
)
add_executable(appsvc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appsvc ALIAS appsvc)

##########################################################################
# Link
##########################################################################
target_link_libraries(appsvc PUBLIC )

target_link_libraries(appsvc
  PRIVATE
    Threads::Threads
    ${OPENSSL_LIBRARIES}
    boost_regex boost_thread boost_system
    cpprest
    ACE
    log4cpp
    common
    prometheus
)

##########################################################################
# install
##########################################################################
install(TARGETS appsvc
    RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/bin
)
