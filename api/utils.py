from currency_converter import CurrencyConverter

def get_size(file):
    return file.size <= 1*1048576


supported_currency = ['GBP', 'CAD', 'SEK', 'SKK', 'RON', 'CYP', 'PLN', 'PHP', 
'ROL', 'AUD', 'INR', 'CHF', 'SGD', 'NZD', 'LTL', 'MTL', 'BRL', 'ISK', 'KRW', 
'JPY', 'USD', 'IDR', 'HKD', 'TRY', 'ZAR', 'MYR', 'ILS', 'EEK', 'RUB', 'NOK', 
'LVL', 'CNY', 'HUF', 'SIT', 'CZK', 'HRK', 'DKK', 'MXN', 'TRL', 'THB', 'BGN', 'EUR']


def currency_convertor(amount, default_currency):
    currencyData = CurrencyConverter()
    try:
        convertAmount = currencyData.convert(amount, 'USD', default_currency)
        return round(convertAmount, 2)
    except:
        converted_amount = currencyData.convert(amount, 'USD', 'USD')
        return round(converted_amount, 2)