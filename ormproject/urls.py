from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from orm.admin import admin_site
from orm import views
from orm.views import setup_license,network_tools_page,network_discovery,approve_approval_request,update_risk_owners,risk_chart_owner_view,update_risk_field,risk_list_view,risk_detail_view,generate_soa,risk_pivot_view, new_risk_heatmap_view, get_risk_details,procedure_design_view,risk_proposals_page,create_categories_from_proposals,create_related_indicators_from_proposals,create_actions_from_proposals
from django.views.generic import TemplateView
from django.http import HttpResponse
from orm.views import assessment_detail,run_assessment,CounterpartyDeleteView,CounterpartyUpdateView,CounterpartyCreateView,CounterpartyListView,calendar_view, get_calendar_events,list_db_tables
from django.contrib.auth import views as auth_views  # Added for authentication views
from django.urls import path
from orm.views import (
    KYCStandardListView, KYCStandardCreateView, KYCStandardUpdateView, KYCStandardDeleteView,
    KYCQuestionListView, KYCQuestionCreateView, KYCQuestionUpdateView, KYCQuestionDeleteView,sanctions_search_view
)
from django.views.i18n import set_language  # Import set_language




urlpatterns = [
    

    
    path("risk/search/", views.risk_search, name="risk_search"),

    
    path('set-language/', set_language, name='set_language'),  # Add this line
    
    path('', views.external_tools_view, name='external_tools'),

    
    # App-specific URLs
    path('risk-pivot-table/', risk_pivot_view, name='risk_pivot_table'),
    path('calendar/', calendar_view, name='calendar_view'),
    path('calendar/events/', views.get_calendar_events, name='get_calendar_events'),

    path('reports/', views.reports_landing_page, name='reports_landing_page'),
   
   
    path('generate_it_risk_report/', views.generate_it_risk_report, name='generate_it_risk_report'),

   
   
   
    path('generate_project_risk_report/', views.generate_project_risk_report, name='generate_project_risk_report'),
   
    path('generate_annual_report_gr/', views.generate_annual_report_gr, name='generate_annual_report_gr'),
   
   
    path('generate_project_risk_report_en/', views.generate_project_risk_report_en, name='generate_project_risk_report_en'),
  
    path('generate-annual-report-en/', views.generate_annual_report_en, name='generate_annual_report_en'),
   
    path('residual-risk-pivot/', views.residual_risk_table_view, name='residual_risk_pivot'),
    path('residual-risk-pivot-portfolio/', views.residual_risk_table_view_portfolio, name='residual_risk_pivot_portfolio'),


    path('report/new/', views.generate_new_report, name='generate_new_report'),


    path('mammoth-risks-report/', views.generate_mammoth_risks_report, name='mammoth_risks_report'),




    path('get-risk-details/', get_risk_details, name='get_risk_details'),  # New URL for risk details
    path('landing-page/', views.landing_page_view, name='landing_page'),
    path('ermapp/', views.ermapp_view, name='ermapp_view'),  # URL for the new view
    path('save-risk-data/', views.save_risk_data, name='save_risk_data'),
    path('admin-pivots/', views.admin_pivots_view, name='admin_pivots'),
    path('portfolio-report/', views.user_portfolio_report, name='user_portfolio_report'),
    path('it-report/', views.user_it_report, name='user_it_report'),

    path('run-create-approval-requests/', views.run_create_approval_requests, name='run_create_approval_requests'),
    path('run-send-pending-approvals-and-actions/', views.run_send_pending_approvals_and_actions, name='run_send_pending_approvals_and_actions'),
    path('generate_country_risk_report/<str:country>/', views.generate_country_risk_report, name='generate_country_risk_report'),
    path('imf-reports/', views.imf_reports_view, name='imf_reports_view'),
    path('delete-risk/<int:risk_id>/', views.delete_risk, name='delete_risk'),

    path('procedure-design/', procedure_design_view, name='procedure_design'),
    path('save-diagram/', views.save_diagram, name='save_diagram'),
    path('get-diagram/<str:name>/', views.get_diagram, name='get_diagram'),
    path('delete-diagram/<str:name>/', views.delete_diagram, name='delete_diagram'),
    path('list-diagrams/', views.list_diagrams, name='list_diagrams'),

    path('db-tables/', list_db_tables, name='list_db_tables'),

    path('risk/proposals-page/', risk_proposals_page, name='risk_proposals_page'),  # Remove risk_id parameter
    path('risk-selection/', views.risk_selection_landing, name='risk_selection_landing'),
    path('generate-report/', views.generate_selected_risks_report, name='generate_selected_risks_report'),
    path('create-mitigations/', views.create_mitigations_from_proposals, name='create_mitigations_from_proposals'),
    path('create-related-risks/', views.create_related_risks_from_proposals, name='create_related_risks_from_proposals'),
    path('create-indicators/', create_related_indicators_from_proposals, name='create_related_indicators_from_proposals'),
    path('create-actions/', create_actions_from_proposals, name='create_actions_from_proposals'),
    path('create-categories/', create_categories_from_proposals, name='create_categories_from_proposals'),

    path('risk-apetite/', views.risk_apetite_view, name='risk_apetite'),
    path('assets-with-risks/', views.ITAssetRiskListView.as_view(), name='assets_with_risks'),

    path('risk-chart/', views.risk_chart_view, name='risk_chart'),
    path('risk-chart-porfolio/', views.risk_chart_view_portfolio, name='risk_chart_porfolio'),
    
    path('risk-chart-owner/', risk_chart_owner_view, name='risk_chart_owner'),
    path('new-heatmap/', new_risk_heatmap_view, name='new_risk_heatmap_view'),

    

    path('add-incident/', views.add_incident, name='add_incident'),  # URL for adding an incident

    path('risk-network/', views.risk_network_view, name='risk_network'),

    path('process_user_input/', views.process_user_input, name='process_user_input'),
    path('create-proposals/', views.create_proposals_with_portfolio, name='create_proposals_with_portfolio'),
    path('create-risk-mitigation-associations/', views.create_risk_mitigation_associations, name='create_risk_mitigation_associations'),

    path('soa/', generate_soa, name='generate_soa'),
    path('soa/save/', views.save_soa, name='save_soa'),  # New URL for saving rationales


    
    path('update-category/<int:risk_id>/', views.update_category, name='update_category'),
    path('risk/<int:pk>/update_treatment/', views.UpdateRiskTreatmentView.as_view(), name='update_risk_treatment'),

    path('risk/<int:risk_id>/autosave/', views.autosave_risk, name='autosave_risk'),
    path('risk/<int:risk_id>/link_itasset/', views.link_itasset, name='link_itasset'),
    path('risk/<int:risk_id>/unlink_itasset/', views.unlink_itasset, name='unlink_itasset'),
    path('risk/<int:risk_id>/link_procedure/', views.link_procedure, name='link_procedure'),
    path('risk/<int:risk_id>/unlink_procedure/', views.unlink_procedure, name='unlink_procedure'),
    # URL for linking an existing mitigation to a risk
    path('risk/<int:risk_id>/link_mitigation/', views.link_mitigation, name='link_mitigation'),
    path('risk/<int:risk_id>/replicate/', views.replicate_risk, name='replicate_risk'),

    # URL for unlinking a mitigation from a risk
    path('risk/<int:risk_id>/unlink_mitigation/', views.unlink_mitigation, name='unlink_mitigation'),
    path('risk/<int:risk_id>/add_itasset/', views.add_itasset_to_risk, name='add_itasset_to_risk'),

    path('risk/<int:risk_id>/add_event/', views.add_event, name='add_event'),

    path('risk/<int:risk_id>/add_mitigation/', views.add_mitigation_to_risk, name='add_mitigation_to_risk'),
    path('mitigation/add/', views.add_mitigation, name='add_mitigation'),
    path('risk/<int:risk_id>/mitigation/save/', views.save_mitigation, name='save_mitigation'),

    path('risk/<int:risk_id>/link_opportunity/', views.link_opportunity, name='link_opportunity'),
    path('risk/<int:risk_id>/unlink_opportunity/', views.unlink_opportunity, name='unlink_opportunity'),
    path('risk/<int:risk_id>/add_opportunity/', views.add_opportunity_to_risk, name='add_opportunity_to_risk'),
    path('risk/<int:risk_id>/link_threat/', views.link_threat, name='link_threat'),
    path('risk/<int:risk_id>/unlink_threat/', views.unlink_threat, name='unlink_threat'),
    path('risk/<int:risk_id>/add_threat/', views.add_threat_to_risk, name='add_threat'),
    path('risk/<int:risk_id>/update/', views.update_risk, name='update_risk'),


    path('risk/<int:risk_id>/add_procedure/', views.add_procedure, name='add_procedure'),

    path('risk/', risk_detail_view, name='risk_detail'),  # For new risk
    path('risk/<int:risk_id>/', risk_detail_view, name='risk_detail'),  # For existing risk


    path('risk/<int:risk_id>/', risk_detail_view, name='risk_detail'),
    path('risk/', risk_detail_view, name='risk_detail'),  # For creating a new risk

    path('risk/<int:risk_id>/link_mitigation/', views.link_mitigation, name='link_mitigation'),
    path('risk/<int:risk_id>/unlink_mitigation/', views.unlink_mitigation, name='unlink_mitigation'),
    path('mitigation/save/', views.save_mitigation, name='save_mitigation'),




    path('action/add/', views.add_action, name='add_action'),
    
    path('indicator/add/', views.add_indicator, name='add_indicator'),
    
    path('risk/add/', views.add_risk_view, name='add_risk'),

    path('risk/<int:risk_id>/delete/', views.delete_risk, name='delete_risk'),
    
    path('risk/<int:risk_id>/update_owners/', update_risk_owners, name='update_risk_owners'),
    





    
    # ------------------------------
    


    path('network-tools/', network_tools_page, name='network_tools'),

    path('network-discovery/', network_discovery, name='network_discovery'),
    path('scan-ports/<str:ip_address>/', views.scan_ports, name='scan_ports'),

    path('run-exploits/', views.run_exploits, name='run_exploits'),

    

        # Counterparty CRUD URLs
    path('counterparties/', CounterpartyListView.as_view(), name='counterparty_list'),
    path('counterparties/add/', CounterpartyCreateView.as_view(), name='counterparty_add'),
    path('counterparties/<int:pk>/edit/', CounterpartyUpdateView.as_view(), name='counterparty_edit'),
    path('counterparties/<int:pk>/delete/', CounterpartyDeleteView.as_view(), name='counterparty_delete'),


    # Assessment URLs
    # path('counterparties/<int:pk>/edit/', views.counterparty_detail, name='counterparty_edit'),
    path('counterparties/<int:pk>/assessments/add/', views.run_assessment, name='assessment_add'),
    path('counterparties/<int:pk>/assessments/', views.AssessmentListView.as_view(), name='assessment_list'),
    path('assessments/<int:pk>/', views.assessment_detail, name='assessment_detail'),
    # KYCStandard URLs
    path('kyc-standards/', KYCStandardListView.as_view(), name='kyc_standard_list'),
    path('kyc-standards/add/', KYCStandardCreateView.as_view(), name='kyc_standard_add'),
    path('kyc-standards/<int:pk>/edit/', KYCStandardUpdateView.as_view(), name='kyc_standard_edit'),
    path('kyc-standards/<int:pk>/delete/', KYCStandardDeleteView.as_view(), name='kyc_standard_delete'),

    # KYCQuestion URLs
    path('kyc-questions/', KYCQuestionListView.as_view(), name='kyc_question_list'),
    path('kyc-questions/add/', KYCQuestionCreateView.as_view(), name='kyc_question_add'),
    path('kyc-questions/<int:pk>/edit/', KYCQuestionUpdateView.as_view(), name='kyc_question_edit'),
    path('kyc-questions/<int:pk>/delete/', KYCQuestionDeleteView.as_view(), name='kyc_question_delete'),


    path("sanctions/search/", sanctions_search_view, name="sanctions_search"),

    path('sanctions_network/', views.sanctions_network_search, name='sanctions_network_search'),
    path("save_clean_result/", views.save_clean_result, name="save_clean_result"),

    path("risk_assessments/", views.risk_assessment_list_view, name="risk_assessment_list"),
    path("risk_assessments/<int:assessment_id>/", views.risk_assessment_detail_view, name="risk_assessment_detail"),
    path("risk_assessments/new/", views.risk_assessment_create_view, name="risk_assessment_create"),
    path("risk_assessments/<int:assessment_id>/delete/", views.risk_assessment_delete_view, name="risk_assessment_delete"),




    path('risk_assessments/<int:assessment_id>/', views.risk_assessment_detail_view, name='risk_assessment_detail'),
    path('risk_assessments/<int:assessment_id>/add_existing_risk/', views.add_risk_to_assessment, name='add_risk_to_assessment'),
    path('risk_assessments/<int:assessment_id>/remove_risk/', views.remove_risk_from_assessment, name='remove_risk_from_assessment'),
    path('risk_assessments/<int:assessment_id>/complete/', views.mark_risk_assessment_completed_view, name='mark_risk_assessment_completed'),
    path('save_assessment/<int:assessment_id>/', views.save_assessment_view, name='save_assessment'),


    path('mitigations/', views.mitigation_list, name='mitigation_list'),
    path('mitigations/<int:mitigation_id>/', views.mitigation_detail, name='mitigation_detail'),
    path('mitigations/<int:mitigation_id>/update/', views.update_mitigation, name='update_mitigation'),

# xAI
    path('chat/', views.chat_view, name='chat_view'),        
     
    # Open AI AGENT
    
    path("chat-page-o/", views.chat_page_o, name="chat_page_o"),  # UI page
    path("chat-o/", views.chat_view_o, name="chat_view_o"),  # API endpoint
    path("upload-file/", views.upload_file, name="upload_file"),

    path("upload-file-to-openai/", views.upload_file_to_openai, name="upload-file-to-openai"),
    path("search-file-on-openai/", views.search_file_on_openai, name="search-file-on-openai"),

    path("agent-explorer/", views.agent_explorer_page, name="agent_explorer"),
    path("agent-explorer/api/", views.agent_explorer_api, name="agent_explorer_api"),



    path('actions/', views.action_list_view, name='action_list'),
    path('action_detail/<int:pk>/', views.action_detail_view, name='action_detail'),

    path('actions/add/', views.ActionCreateView.as_view(), name='action_add'),
    path('actions/<int:pk>/update/', views.ActionUpdateView.as_view(), name='action_update'),
    
    path('actions/link/', views.link_action, name='link_action'),
    path('actions/unlink/', views.unlink_action, name='unlink_action'),
    path('actions/available/<int:risk_id>/', views.available_actions, name='available_actions'),
    path('indicators/link/', views.link_indicator, name='link_indicator'),
    path('indicators/unlink/', views.unlink_indicator, name='unlink_indicator'),

    path('action/<int:action_id>/link_risk/', views.LinkRiskView.as_view(), name='link_risk'),
    path('action/<int:action_id>/unlink_risk/', views.UnlinkRiskView.as_view(), name='unlink_risk'),


    path('opportunities/', views.OpportunityListView.as_view(), name='opportunity_list'),
    path('opportunities/<int:pk>/', views.OpportunityDetailView.as_view(), name='opportunity_detail'),
    path('opportunity/<int:pk>/link_risk/', views.LinkRiskView.as_view(), name='link_risk'),
    path('opportunity/<int:pk>/unlink_risk/', views.UnlinkRiskView.as_view(), name='unlink_risk'),
    path('opportunity/<int:pk>/edit/', views.OpportunityUpdateView.as_view(), name='opportunity_edit'),



    path('threats/', views.ThreatListView.as_view(), name='threat_list'),
    path('threats/add/', views.ThreatCreateView.as_view(), name='threat_add'),
    path('threats/<int:pk>/edit/', views.ThreatUpdateView.as_view(), name='threat_edit'),
    path('threats/<int:pk>/delete/', views.ThreatDeleteView.as_view(), name='threat_delete'),

    path('threat/<int:pk>/add_risk/', views.ThreatLinkRiskView.as_view(), name='add_threat_risk'),
    path('threat/<int:pk>/remove_risk/', views.ThreatUnlinkRiskView.as_view(), name='remove_threat_risk'),

    path('threat/<int:pk>/', views.ThreatDetailView.as_view(), name='threat_detail'),
    path('threats/<int:pk>/', views.ThreatDetailView.as_view(), name='threat_detail'),





   path('categories/', views.CategoryListView.as_view(), name='category_list'),
   path('categories/<int:pk>/', views.CategoryDetailView.as_view(), name='category_detail'),
   path('categories/add/', views.CategoryCreateView.as_view(), name='category_add'),

   path('portfolios/', views.PortfolioListView.as_view(), name='portfolio_list'),
   path('portfolios/<int:pk>/', views.PortfolioDetailView.as_view(), name='portfolio_detail'),
   path('portfolios/add/', views.PortfolioCreateView.as_view(), name='portfolio_add'),
   path('portfolios/<int:pk>/edit/', views.PortfolioUpdateView.as_view(), name='portfolio_update'),

    path('itassets/', views.ITAssetListView.as_view(), name='itasset_list'),
    path('itassets/add/', views.ITAssetCreateView.as_view(), name='itasset_add'),
    path('itassets/<int:pk>/', views.ITAssetDetailView.as_view(), name='itasset_detail'),
    path('itassets/<int:pk>/edit/', views.ITAssetUpdateView.as_view(), name='itasset_edit'),
    path('itassets/<int:pk>/delete/', views.ITAssetDeleteView.as_view(), name='itasset_delete'),
    path('itasset/<int:itasset_id>/link_risk/', views.link_risk_to_itasset, name='link_risk_to_itasset'),
    path('itasset/<int:itasset_id>/unlink_risk/', views.unlink_risk_from_itasset, name='unlink_risk_from_itasset'),
   
    path('itthreat/', views.itthreat_list, name='itthreat_list'),
    path('itthreat/<int:threat_id>/', views.itthreat_detail, name='itthreat_detail'),

    path('vulnerability/', views.vulnerability_list, name='vulnerability_list'),
    path('vulnerability/<int:vulnerability_id>/', views.vulnerability_detail, name='vulnerability_detail'),
   
   
    path('approval-requests/', views.ApprovalRequestListView.as_view(), name='approval_request_list'),
    path('approval-requests/add/', views.ApprovalRequestCreateView.as_view(), name='approval_request_add'),
    path('approval-requests/<int:pk>/', views.ApprovalRequestDetailView.as_view(), name='approval_request_detail'),
    path('approval-requests/<int:pk>/edit/', views.ApprovalRequestUpdateView.as_view(), name='approval_request_edit'),
    path('approval-requests/<int:pk>/delete/', views.ApprovalRequestDeleteView.as_view(), name='approval_request_delete'),
    path('approval-requests/approve-bulk/', views.ApprovalRequestApproveBulkView.as_view(), name='approval_request_approve_bulk'),
    path('approval-control/', views.approval_control_view, name='approval_control'),
    path('approval/<int:approval_id>/approve/', approve_approval_request, name='approve-approval'),


    path('indicators/', views.IndicatorListView.as_view(), name='indicator_list'),
    path('indicators/add/', views.IndicatorCreateView.as_view(), name='indicator_add'),
    path('indicators/<int:pk>/', views.IndicatorDetailView.as_view(), name='indicator_detail'),
    path('indicators/<int:pk>/edit/', views.IndicatorUpdateView.as_view(), name='indicator_edit'),
    path('indicators/<int:pk>/delete/', views.IndicatorDeleteView.as_view(), name='indicator_delete'),


    path('procedures/', views.ProcedureListView.as_view(), name='procedure_list'),
    path('procedures/add/', views.ProcedureCreateView.as_view(), name='procedure_add'),
    path('procedures/<int:pk>/', views.ProcedureDetailView.as_view(), name='procedure_detail'),
    path('procedures/<int:pk>/edit/', views.ProcedureUpdateView.as_view(), name='procedure_edit'),
    path('procedures/<int:pk>/delete/', views.ProcedureDeleteView.as_view(), name='procedure_delete'),


    path('events/', views.EventListView.as_view(), name='event_list'),
    path('events/add/', views.EventCreateView.as_view(), name='event_add'),
    path('events/<int:pk>/', views.EventDetailView.as_view(), name='event_detail'),
    path('events/<int:pk>/edit/', views.EventUpdateView.as_view(), name='event_edit'),
    path('events/<int:pk>/delete/', views.EventDeleteView.as_view(), name='event_delete'),
    path('events/<int:event_id>/unlink_risk/<int:risk_id>/', views.unlink_risk, name='unlink_risk'),
    path('events/<int:event_id>/link_risk/', views.link_risk_to_event, name='link_risk_to_event'),




    path('documents/', views.document_list, name='document_list'),
    path('documents/upload/', views.upload_document, name='upload_document'),
    path('documents/delete/<int:document_id>/', views.delete_document, name='delete_document'),
    path('documents/edit/<int:document_id>/', views.edit_document, name='edit_document'),
    path('documents/versions/<int:document_id>/', views.document_versions, name='document_versions'),
    path('documents/delete_folder/<int:folder_id>/', views.delete_folder, name='delete_folder'),
    path('documents/create_folder/', views.create_folder, name='create_folder'),
    
    path('documents/edit_folder/<int:folder_id>/', views.edit_folder, name='edit_folder'),
    path('documents/delete_folder/<int:folder_id>/', views.delete_folder, name='delete_folder'),
    path('document/preview/<int:doc_id>/', views.document_preview, name='document_preview'),


    path("select-users/", views.select_recipients_view, name="select_users"),
    path("generate-email/", views.generate_email_view, name="generate_email_view"),
    path('filter-portfolios/', views.filter_portfolios_by_user, name='filter_portfolios_by_user'),  # ✅ Add this!
    path("email-tracking/", views.email_tracking_dashboard, name="email_tracking_dashboard"),
    path("track-response/", views.mark_email_as_responded, name="mark_email_as_responded"),
    path("email-response/<int:email_id>/", views.email_response_view, name="email-response"),
    path("email/<int:email_id>/", views.email_detail_view, name="email_detail_view"),



    path('risks/', risk_list_view, name='risk_list'),
    path('risks_new/', views.risk_list_view_new, name='risk_list_new'),
    
    
    
    
    path('risks_new/', views.risk_list_view_new, name='risk_list_new'),
    # path('load-portfolio-risks/<int:portfolio_id>/', views.load_portfolio_risks, name='load_portfolio_risks'),
    
    
    path('risk/<int:risk_id>/', views.risk_detail_view, name='risk_detail_view'),

    path('risk/<int:risk_id>/link_event/', views.link_event_to_risk, name='link_event'),



    path("loan-checker/", views.loan_checker_view, name="loan_checker"),


    path('upload/', views.kyc_upload, name='kyc_upload'),



    path('fractal/', views.fractal_view, name='fractal'),



# ADMIN ------------------------------
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password-reset'),
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('user/password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),


    path('license-setup/', setup_license, name='license_setup'),

    path('admin/', admin_site.urls),  # Root URL now points to the custom admin site

    # Fallback Admin URL Patterns for Authentication
    path('admin/login/', auth_views.LoginView.as_view(), name='admin_login'),  # Added to handle admin login explicitly
    path('admin/logout/', auth_views.LogoutView.as_view(), name='admin_logout'),  # Added to handle admin logout explicitly
    path('admin/password_change/', auth_views.PasswordChangeView.as_view(), name='admin_password_change'),  # Added for password change
    path('admin/password_change/done/', auth_views.PasswordChangeDoneView.as_view(), name='admin_password_change_done'),  # Password change done page
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='registration/logout.html'), name='logout'),
    path('password_change/', auth_views.PasswordChangeView.as_view(
        template_name='registration/password_change.html'), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(
        template_name='registration/password_change_done.html'), name='password_change_done'),
    path('user-activity/', views.user_activity_dashboard, name='user_activity_dashboard'),
    path('user-activity-data/', views.user_activity_data, name='user_activity_data'),

]

# Serving static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
