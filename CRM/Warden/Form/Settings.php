<?php

declare(strict_types = 1);

class CRM_Warden_Form_Settings extends CRM_Admin_Form_Generic {

  public function getTemplateFileName(): string {
    return 'CRM/Admin/Form/Generic.tpl';
  }

  public function getSettingPageFilter(): string {
    return 'warden';
  }

}
